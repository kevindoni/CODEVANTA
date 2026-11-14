"""``codevanta apk`` / ``codevanta js`` / ``codevanta certs`` depth bridges.

Registered in :mod:`codevanta.cli.main` with exactly one ``add_typer`` block
(three sub-apps, one block). Every command maps the typed
:class:`~codevanta.core.report.AnalysisError` of its bridge to ``exit 2``
with the error's install hint -- never a traceback -- prints tables with an
``evidence:`` footer like the other lanes, and supports ``--json`` for the
unchanged ``to_dict()`` payload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.apktool_bridge import apk_decode
from codevanta.analysis.pe_certs import inspect_cert_table
from codevanta.analysis.wakaru_bridge import MODE_MINIFY, MODES, js_recover
from codevanta.core.report import AnalysisError

apk_app = typer.Typer(help="Android APK decoding via apktool (requires apktool on PATH)")
js_app = typer.Typer(help="JS bundle recovery via Wakaru (requires Node/npm)")
certs_app = typer.Typer(
    invoke_without_command=True,
    # Single-command sub-app: PATH and --json may appear in any order.
    context_settings={"allow_interspersed_args": True},
    help="PE certificate table parsing (pure Python, offline).",
)
console = Console()


def _fail(message: str, code: int = 2) -> NoReturn:
    """Print an error and exit with ``code`` (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=code) from None


def _evidence_footer(evidence: dict[str, Any]) -> None:
    """Print the shared ``evidence:`` footer line."""
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source')))}"
        f" via {escape(str(evidence.get('method')))}"
        f" · confidence: {escape(str(evidence.get('confidence')))}[/]"
    )

def _warnings_lines(warnings: list[str]) -> None:
    """Print each surprise as a ``warning:`` line (dim)."""
    for warning in warnings:
        console.print(f"[dim]warning: {escape(warning)}[/]")


@apk_app.command("decode")
def apk_decode_cmd(
    apk: Annotated[Path, typer.Argument(help="APK file to decode")],
    out_dir: Annotated[
        Path, typer.Option("--out-dir", help="Directory for the decoded tree")
    ],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Decode an APK's manifest and resources with apktool (--no-src, bounded)."""
    try:
        result = apk_decode(apk, out_dir)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"apktool decode · {escape(payload['apk'])}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("out_dir", escape(str(payload["out_dir"])))
    table.add_row(
        "AndroidManifest.xml",
        "decoded" if payload["manifest_decoded"] else "missing",
    )
    table.add_row("apktool.yml", "present" if payload["apktool_yml"] else "missing")
    table.add_row("res/ files", str(payload["res_count"]))
    table.add_row(
        "smali",
        "present" if payload["smali_present"] else "absent (expected with --no-src)",
    )
    table.add_row("top-level entries", str(len(payload["entries"])))
    framework = payload.get("framework_version")
    if framework:
        table.add_row("apktool version", escape(str(framework)))
    console.print(table)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@js_app.command("recover")
def js_recover_cmd(
    bundle: Annotated[Path, typer.Argument(help="Minified or bundled JS file")],
    out_dir: Annotated[
        Path, typer.Option("--out-dir", help="Directory for recovered output")
    ],
    mode: Annotated[
        str,
        typer.Option("--mode", help="'minify' (unminify) or 'unpack' (split modules)"),
    ] = MODE_MINIFY,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Recover readable JavaScript from a bundle with Wakaru (bounded)."""
    if mode.strip().lower() not in MODES:
        _fail(f"invalid mode {mode!r}; expected one of {', '.join(MODES)}")
    try:
        result = js_recover(bundle, out_dir, mode)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"wakaru {escape(payload['mode'])} · {escape(payload['bundle'])}")
    table.add_column("Source")
    table.add_column("Recovered")
    table.add_column("Note")
    for entry in payload["entries"]:
        table.add_row(
            escape(str(entry["source"])),
            escape(str(entry.get("target", "-"))),
            escape(str(entry.get("note", ""))),
        )
    console.print(table)
    footer = f"[dim]recovered: {payload['count']} entry(ies)"
    if payload.get("module_count") is not None:
        footer += f" · modules: {payload['module_count']}"
    if payload.get("packer"):
        footer += f" · packer: {escape(str(payload['packer']))}"
    if payload.get("transcript_path"):
        footer += f" · transcript: {escape(str(payload['transcript_path']))}"
    console.print(footer + "[/]")
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@certs_app.callback(invoke_without_command=True)
def certs(
    path: Annotated[Path, typer.Argument(help="PE file to inspect")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Parse a PE file's certificate table (pure Python, offline, no trust checks)."""
    try:
        result = inspect_cert_table(path)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"certificate table · {escape(str(path))}")
    table.add_column("Signer")
    table.add_column("Serial")
    table.add_column("Digest")
    table.add_column("Signature")
    table.add_column("Signing time")
    for signer in payload["signers"]:
        table.add_row(
            str(signer["index"]),
            escape(str(signer["serial_hex"] or "-")),
            escape(str(signer["digest_algorithm"])),
            escape(str(signer["signature_algorithm"])),
            escape(str(signer["signing_time"] or "-")),
        )
    if not payload["signers"]:
        table.add_row("-", "-", "-", "-", "-")
    console.print(table)
    console.print(
        f"[dim]status: {escape(str(payload['status']))} · entries: {payload['entries']}"
        f" · signers: {payload['signer_count']}"
        + (
            f" · gaps: {escape(', '.join(payload['gaps']))}"
            if payload["gaps"]
            else ""
        )
        + "[/]"
    )
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])

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
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.apktool_bridge import apk_decode
from codevanta.analysis.electron_audit import DEFAULT_MAX_FILES as AUDIT_DEFAULT_MAX_FILES
from codevanta.analysis.electron_audit import MAX_FILES as AUDIT_MAX_FILES
from codevanta.analysis.electron_audit import audit_electron_app
from codevanta.analysis.javascript import DEFAULT_MAX_FILES as JS_DEFAULT_MAX_FILES
from codevanta.analysis.javascript import MAX_FILES as JS_MAX_FILES
from codevanta.analysis.javascript import analyze_javascript_app
from codevanta.analysis.js_diff import compare_js_apps
from codevanta.analysis.pe_certs import inspect_cert_table
from codevanta.analysis.wakaru_bridge import MODE_MINIFY, MODES, js_recover
from codevanta.cli.console import make_console
from codevanta.core.report import AnalysisError

apk_app = typer.Typer(help="Android APK decoding via apktool (requires apktool on PATH)")
js_app = typer.Typer(
    help="JS analysis: static app inventory (offline) and bundle recovery via Wakaru"
)
certs_app = typer.Typer(
    invoke_without_command=True,
    # Single-command sub-app: PATH and --json may appear in any order.
    context_settings={"allow_interspersed_args": True},
    help="PE certificate table parsing (pure Python, offline).",
)
console = make_console()


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


@js_app.command("analyze")
def js_analyze_cmd(
    app_path: Annotated[
        Path,
        typer.Argument(help="Extracted app directory or .asar archive"),
    ],
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files",
            help=f"Ceiling on file rows kept (1..{JS_MAX_FILES})",
        ),
    ] = JS_DEFAULT_MAX_FILES,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Statically inventory a JavaScript/Electron app (offline, bounded)."""
    try:
        result = analyze_javascript_app(app_path, max_files=max_files)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    kind = payload["kind"]
    table = Table(title=f"js analyze · {escape(payload['root'])} ({kind})")
    table.add_column("File")
    table.add_column("Role", justify="right")
    table.add_column("Imports", justify="right")
    table.add_column("IPC", justify="right")
    for js_file in payload["files"]:
        table.add_row(
            escape(str(js_file["path"])),
            escape(str(js_file["role"])),
            str(len(js_file["imports"])),
            str(len(js_file["ipc"])),
        )
    console.print(table)
    package = payload.get("package")
    if package:
        name = package.get("name") or "-"
        main = package.get("main") or "-"
        electron = package.get("electron_version") or "-"
        console.print(
            f"[dim]package: {escape(str(name))} · main: {escape(str(main))}"
            f" · electron: {escape(str(electron))}[/]"
        )
    pairs = payload["ipc"]["pairs"]
    if pairs:
        ipc_table = Table(title="IPC boundaries (main <-> renderer)")
        ipc_table.add_column("Channel")
        ipc_table.add_column("Main side", justify="right")
        ipc_table.add_column("Renderer side", justify="right")
        for pair in pairs:
            ipc_table.add_row(
                escape(str(pair["channel"])),
                ", ".join(f"{s['api']}:{s['line']}" for s in pair["main"]) or "-",
                ", ".join(f"{s['api']}:{s['line']}" for s in pair["renderer"]) or "-",
            )
        console.print(ipc_table)
    packages = payload["external_packages"]
    if packages:
        console.print(
            f"[dim]external packages: {escape(', '.join(packages)) or '-'}[/]"
        )
    skipped = payload["skipped"]
    console.print(
        f"[dim]files: {payload['file_count']} (scanned {payload['files_scanned']})"
        f" · skipped dirs: {skipped['directories']}"
        f" · large: {skipped['large_files']}"
        f" · truncated: {'yes' if payload['truncated'] else 'no'}[/]"
    )
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@js_app.command("audit")
def js_audit_cmd(
    app_path: Annotated[
        Path,
        typer.Argument(help="Extracted app directory or .asar archive"),
    ],
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files",
            help=f"Ceiling on file rows kept (1..{AUDIT_MAX_FILES})",
        ),
    ] = AUDIT_DEFAULT_MAX_FILES,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Audit an Electron app for security anti-patterns (offline, bounded)."""
    try:
        result = audit_electron_app(app_path, max_files=max_files)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    if payload["findings"]:
        table = Table(title=f"electron audit · {escape(payload['root'])} ({payload['kind']})")
        table.add_column("Severity", justify="right")
        table.add_column("Rule")
        table.add_column("File:Line")
        table.add_column("Finding")
        for finding in payload["findings"]:
            table.add_row(
                escape(str(finding["severity"])),
                escape(str(finding["rule_id"])),
                f"{escape(str(finding['file']))}:{finding['line']}",
                escape(str(finding["title"])),
            )
        console.print(table)
    else:
        console.print(
            f"[green]no findings[/] · {escape(payload['root'])} ({payload['kind']})"
        )
    summary = payload["summary"]
    console.print(
        f"[dim]findings: {payload['finding_count']}"
        f" · critical: {summary.get('critical', 0)}"
        f" · high: {summary.get('high', 0)}"
        f" · medium: {summary.get('medium', 0)}"
        f" · files scanned: {payload['scanned_files']}"
        f" · truncated: {'yes' if payload['truncated'] else 'no'}[/]"
    )
    for finding in payload["findings"]:
        recommendation = finding.get("recommendation")
        if recommendation:
            console.print(
                f"[dim]fix {escape(str(finding['rule_id']))}: {escape(str(recommendation))}[/]"
            )
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@js_app.command("diff")
def js_diff_cmd(
    left_path: Annotated[
        Path,
        typer.Argument(help="Older app side: extracted directory or .asar archive"),
    ],
    right_path: Annotated[
        Path,
        typer.Argument(help="Newer app side: extracted directory or .asar archive"),
    ],
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files",
            help=f"File-row ceiling passed to both inventories (1..{JS_MAX_FILES})",
        ),
    ] = JS_DEFAULT_MAX_FILES,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Diff two builds of one JavaScript/Electron app (offline, bounded)."""
    try:
        result = compare_js_apps(left_path, right_path, max_files=max_files)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    console.print(
        f"[bold]js diff[/] · {escape(payload['left']['root'])} -> "
        f"{escape(payload['right']['root'])}"
    )
    files = payload["files"]
    console.print(
        f"[dim]files: {files['left_count']} -> {files['right_count']}"
        f" · added: {len(files['added'])}"
        f" · removed: {len(files['removed'])}"
        f" · changed: {len(files['changed'])}"
        f" · role changes: {len(files['role_changes'])}"
        f" · packages: {len(payload['packages'])}"
        f" · ipc: {len(payload['ipc'])}[/]"
    )
    if payload["identical"]:
        console.print("[green]no bounded delta observed[/]")
    if files["changed"]:
        table = Table(title="Changed modules")
        table.add_column("File")
        table.add_column("Role", justify="right")
        table.add_column("Imports +", justify="right")
        table.add_column("Imports -", justify="right")
        for row in files["changed"]:
            table.add_row(
                escape(str(row["path"])),
                f"{escape(str(row['role_left']))} -> {escape(str(row['role_right']))}",
                str(len(row["imports_added"])),
                str(len(row["imports_removed"])),
            )
        console.print(table)
    if payload["packages"]:
        table = Table(title="Dependencies")
        table.add_column("Package")
        table.add_column("Change", justify="right")
        for row in payload["packages"]:
            if row["kind"] == "version":
                change = f"{escape(str(row['version_left']))} -> {escape(str(row['version_right']))}"
            else:
                change = escape(row["kind"])
            table.add_row(escape(str(row["name"])), change)
        console.print(table)
    if payload["ipc"]:
        table = Table(title="IPC boundary changes")
        table.add_column("Channel")
        table.add_column("Change", justify="right")
        table.add_column("Files")
        for row in payload["ipc"]:
            files_text = ", ".join(row.get("files", ())) or "-"
            table.add_row(escape(str(row["channel"])), escape(row["kind"]), escape(files_text))
        console.print(table)
    if payload["truncated"]:
        console.print("[yellow]truncated: one or more lists hit the row cap[/]")
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

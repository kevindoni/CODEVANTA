"""``codevanta frida`` / ``codevanta lldb`` / ``codevanta rizin`` live bridges.

Registered in :mod:`codevanta.cli.main` with exactly one import + one
``add_typer`` block (three sub-apps). Every command maps the typed
:class:`~codevanta.core.report.AnalysisError` of its bridge to ``exit 2``
with the error's install hint -- never a traceback -- prints tables with an
``evidence:`` footer like the other lanes, and supports ``--json`` for the
unchanged ``to_dict()`` payload. All commands are offline-safe: without the
backing tool they exit 2 with the skip-gate message.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.frida_bridge import (
    DEFAULT_DURATION,
    MODE_ATTACH,
    list_devices,
    list_processes,
    start_session,
)
from codevanta.analysis.lldb_bridge import DEFAULT_TIMEOUT as LLDB_DEFAULT_TIMEOUT
from codevanta.analysis.lldb_bridge import run_under_lldb
from codevanta.analysis.rizin_bridge import functions_of, info_of
from codevanta.core.report import AnalysisError

frida_app = typer.Typer(help="Frida live instrumentation (requires the frida CLI tools)")
lldb_app = typer.Typer(help="Batch LLDB runs (requires lldb on PATH)")
rizin_app = typer.Typer(help="rizin batch analysis (requires rizin on PATH)")


@lldb_app.callback()
def _lldb_group() -> None:
    """Force lldb_app down the typer group path.

    typer 0.29's single-command fast path mis-registers the positional
    ``target`` argument (click 8.5, py3.14): ``run`` then rejects its target
    as an "unexpected extra argument". A callback flips the app to the group
    code path, which parses the same argv correctly.
    """


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


@frida_app.command("devices")
def frida_devices_cmd(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """List Frida devices (frida-ls-devices, bounded, skip-gated)."""
    try:
        result = list_devices()
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title="frida devices")
    for column in ("id", "type", "name", "os"):
        table.add_column(column)
    for device in payload["devices"]:
        table.add_row(
            escape(str(device["id"])),
            escape(str(device["type"])),
            escape(str(device["name"])),
            escape(str(device.get("os") or "-")),
        )
    console.print(table)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@frida_app.command("ps")
def frida_ps_cmd(
    device: Annotated[
        str | None, typer.Option("--device", help="Frida device id (frida-ps -D)")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """List processes on a Frida device (frida-ps, bounded, skip-gated)."""
    try:
        result = list_processes(device_id=device)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title="frida processes")
    for column in ("pid", "name", "identifier"):
        table.add_column(column)
    for process in payload["processes"]:
        table.add_row(
            str(process["pid"]),
            escape(str(process["name"])),
            escape(str(process.get("identifier") or "-")),
        )
    console.print(table)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@frida_app.command("script")
def frida_script_cmd(
    pid: Annotated[int, typer.Argument(help="Target process id to attach to")],
    script: Annotated[Path, typer.Argument(help="Frida gadget script (.js, max 64 KiB)")],
    duration: Annotated[
        float,
        typer.Option(
            "--duration",
            help=f"Run budget in seconds (1 .. 60, default {DEFAULT_DURATION:g})",
        ),
    ] = DEFAULT_DURATION,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Run a Frida gadget script on a process (bounded, skip-gated)."""
    if not script.is_file():
        _fail(f"script file not found: {script}")
    try:
        session = start_session(pid, MODE_ATTACH, script_path=script, duration=duration)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = session.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    record = payload.get("result")
    table = Table(title=f"frida script · pid {pid} · {escape(str(script))}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("mode", escape(str(payload["mode"])))
    table.add_row("messages", str(record["message_count"] if record else payload["message_count"]))
    if record is not None and record.get("timeout_reached"):
        table.add_row("duration budget", "reached (process reaped)")
    console.print(table)
    messages = record["messages"] if record else payload["messages"]
    for message in messages[:40]:
        console.print(f"[dim]{escape(message['kind'])}: {escape(message['payload'])}[/]")
    if len(messages) > 40:
        console.print(f"[dim]... {len(messages) - 40} more messages[/]")
    if record is not None:
        _warnings_lines(list(record["warnings"]))
        _evidence_footer(record["evidence"])
    else:
        console.print(
            f"[dim]messages: {payload['message_count']} · "
            f"dropped: {payload['dropped_messages']} · "
            f"resumed: {payload['resumed']} · closed: {payload['closed']}[/]"
        )


@lldb_app.command("run")
def lldb_run_cmd(
    target: Annotated[Path, typer.Argument(help="Executable to run under lldb")],
    break_at: Annotated[
        str,
        typer.Option("--break", help="Breakpoint: function name or 0x address"),
    ] = "",
    timeout_s: Annotated[
        float,
        typer.Option(
            "--timeout",
            help=f"Wall-clock budget in seconds (1 .. 120, default {LLDB_DEFAULT_TIMEOUT:g})",
        ),
    ] = LLDB_DEFAULT_TIMEOUT,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Run a target under a batch lldb session and report stop/registers/frames."""
    try:
        result = run_under_lldb(target, break_at=break_at or None, timeout_s=timeout_s)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"lldb run · {escape(str(target))}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("stop reason", escape(str(payload["stopped_reason"] or "-")))
    table.add_row("registers", str(len(payload["registers"])))
    table.add_row("frames", str(payload["frame_count"]))
    console.print(table)
    if payload["frames"]:
        frames = Table(title="backtrace")
        frames.add_column("#", justify="right")
        frames.add_column("address")
        frames.add_column("module")
        frames.add_column("symbol")
        for frame in payload["frames"]:
            frames.add_row(
                str(frame["index"]),
                escape(str(frame["address"])),
                escape(str(frame["module"] or "-")),
                escape(str(frame["symbol"] or "-")),
            )
        console.print(frames)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@rizin_app.command("functions")
def rizin_functions_cmd(
    file: Annotated[Path, typer.Argument(help="Binary file to analyse (aaa; afl)")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """List functions with rizin batch analysis (bounded 256, skip-gated)."""
    try:
        result = functions_of(file)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"rizin functions · {escape(str(file))}")
    table.add_column("address", justify="right")
    table.add_column("size", justify="right")
    table.add_column("name")
    for function in payload["functions"]:
        table.add_row(
            escape(str(function["address"])),
            escape(str(function.get("size", "-"))),
            escape(str(function["name"])),
        )
    console.print(table)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])


@rizin_app.command("info")
def rizin_info_cmd(
    file: Annotated[Path, typer.Argument(help="Binary file to identify (iI)")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the JSON result instead of tables")
    ] = False,
) -> None:
    """Print the rizin ``iI`` key/value identity report (bounded, skip-gated)."""
    try:
        result = info_of(file)
    except AnalysisError as exc:
        _fail(str(exc))
    payload = result.to_dict()
    if json_output:
        console.print_json(json.dumps(payload))
        return
    table = Table(title=f"rizin info · {escape(str(file))}")
    table.add_column("key")
    table.add_column("value")
    for key, value in payload["fields"].items():
        table.add_row(escape(key), escape(value))
    console.print(table)
    _warnings_lines(payload["warnings"])
    _evidence_footer(payload["evidence"])



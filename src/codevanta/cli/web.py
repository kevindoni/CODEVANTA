"""``codevanta web`` (CDP inspection) and ``codevanta asar`` commands.

The web commands are *passive*: they list debug targets, read a page's
navigation state and resource tree, overhear console traffic for a bounded
window, capture one screenshot, and probe the optional WebMCP domain. They
never send ``Runtime.evaluate`` and never inject anything into the page.
``codevanta asar`` is fully offline: it lists an Electron archive or extracts
one entry into memory (bounded 8 MiB) and writes it next to the caller.

A dead endpoint is a typed exit (code 2) with a one-line reason -- the CLI
never shows a raw socket traceback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis import cdp_client
from codevanta.analysis.asar import (
    MAX_EXTRACT_BYTES,
    extract_file,
    list_archive,
)
from codevanta.analysis.har_capture import load_har
from codevanta.analysis.proto_wire import decode_message, load_proto_bytes
from codevanta.core.report import AnalysisError

web_app = typer.Typer(help="Passive CDP inspection of a live Electron/Chromium")

console = Console(stderr=False)
_err_console = Console(stderr=True)


def _fail(message: str) -> NoReturn:
    """Print one typed error line and exit with code 2."""
    _err_console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=2)


def _print_json(payload: dict[str, Any]) -> None:
    """Print a JSON-safe payload through the shared console."""
    console.print_json(json.dumps(payload))


def _resolve_page_ws_url(target_id: str, endpoint: str) -> str:
    """Resolve a target id to its debugger WebSocket URL (typed failures)."""
    try:
        targets = cdp_client.list_targets(endpoint)
        target = cdp_client.find_target(targets, target_id)
    except AnalysisError as exc:
        _fail(str(exc))
    if target.ws_url is None:
        _fail(f"target {target_id!r} exposes no webSocketDebuggerUrl")
    return target.ws_url


@web_app.command("targets")
def targets(
    endpoint: Annotated[
        str, typer.Option("--endpoint", help="DevTools HTTP endpoint (host:port or URL)")
    ] = cdp_client.DEFAULT_ENDPOINT,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the target list as JSON")
    ] = False,
) -> None:
    """List debug targets exposed by a CDP endpoint."""
    try:
        listing = cdp_client.list_targets(endpoint)
    except AnalysisError as exc:
        _fail(str(exc))
    if json_output:
        _print_json(listing.to_dict())
        return
    table = Table(title=f"CDP targets on {escape(listing.endpoint)}")
    table.add_column("Id")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("Url")
    for target in listing.targets:
        table.add_row(
            escape(target.target_id),
            escape(target.type),
            escape(target.title),
            escape(target.url),
        )
    console.print(table)
    console.print(
        f"[dim]targets: {len(listing.targets)} · evidence: {listing.evidence.source}"
        f"/{listing.evidence.method}[/]"
    )


@web_app.command("inspect")
def inspect(
    target_id: Annotated[str, typer.Argument(help="Target id from `codevanta web targets`")],
    endpoint: Annotated[
        str, typer.Option("--endpoint", help="DevTools HTTP endpoint (host:port or URL)")
    ] = cdp_client.DEFAULT_ENDPOINT,
    observe_ms: Annotated[
        int,
        typer.Option(
            "--observe-ms",
            min=0,
            max=cdp_client.MAX_OBSERVE_MS,
            help="Console observation window in milliseconds",
        ),
    ] = cdp_client.DEFAULT_OBSERVE_MS,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the inspection as JSON")
    ] = False,
) -> None:
    """Passively inspect one page: identity, resources, console traffic."""
    ws_url = _resolve_page_ws_url(target_id, endpoint)
    try:
        result = cdp_client.inspect_page(ws_url, observe_ms=observe_ms)
    except AnalysisError as exc:
        _fail(str(exc))
    if json_output:
        _print_json(result.to_dict())
        return
    console.print(f"[bold]title:[/] {escape(result.title) or '[dim](none)[/]'}")
    console.print(f"[bold]url:[/] {escape(result.url) or '[dim](none)[/]'}")
    table = Table(title="Resources")
    table.add_column("Type")
    table.add_column("Url")
    for resource in result.resources:
        table.add_row(escape(resource.type), escape(resource.url))
    console.print(table)
    console.print(
        f"[dim]resources: {len(result.resources)} (truncated: "
        f"{'yes' if result.resources_truncated else 'no'})[/]"
    )
    console_table = Table(title="Console (observed, passive)")
    console_table.add_column("Level")
    console_table.add_column("Source")
    console_table.add_column("Text")
    for entry in result.console:
        console_table.add_row(escape(entry.level), escape(entry.origin), escape(entry.text))
    console.print(console_table)
    console.print(
        f"[dim]console: {len(result.console)} entries (truncated: "
        f"{'yes' if result.console_truncated else 'no'})"
        f" · observe_ms: {result.observe_ms}"
        f" · evidence: {result.evidence.source}/{result.evidence.method}[/]"
    )


@web_app.command("shot")
def shot(
    target_id: Annotated[str, typer.Argument(help="Target id from `codevanta web targets`")],
    out_png: Annotated[Path, typer.Argument(help="Output PNG path (bounded 20 MiB)")],
    endpoint: Annotated[
        str, typer.Option("--endpoint", help="DevTools HTTP endpoint (host:port or URL)")
    ] = cdp_client.DEFAULT_ENDPOINT,
) -> None:
    """Capture one bounded screenshot of a page (read-only render query)."""
    ws_url = _resolve_page_ws_url(target_id, endpoint)
    try:
        result = cdp_client.capture_screenshot(ws_url, out_png)
    except AnalysisError as exc:
        _fail(str(exc))
    dimensions = f"{result.width or '?'}x{result.height or '?'}"
    console.print(
        f"[dim]saved {escape(result.path)} - {result.byte_count} bytes - {dimensions}"
        f" - evidence: {result.evidence.source}/{result.evidence.method}[/]"
    )


@web_app.command("webmcp")
def webmcp(
    target_id: Annotated[str, typer.Argument(help="Target id from `codevanta web targets`")],
    endpoint: Annotated[
        str, typer.Option("--endpoint", help="DevTools HTTP endpoint (host:port or URL)")
    ] = cdp_client.DEFAULT_ENDPOINT,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the probe result as JSON")
    ] = False,
) -> None:
    """Probe the optional WebMCP domain on a target (tolerates absence)."""
    ws_url = _resolve_page_ws_url(target_id, endpoint)
    probe = cdp_client.webmcp_get_tools(ws_url)
    if json_output:
        _print_json(probe.to_dict())
        return
    if not probe.available:
        console.print(f"[yellow]WebMCP unavailable:[/] {escape(probe.reason or '?')}")
    else:
        console.print("[bold]WebMCP tools:[/]")
        for tool in probe.tools:
            description = tool.description or ""
            console.print(f"  {escape(tool.name)}  [dim]{escape(description)}[/]")
    console.print(
        f"[dim]available: {'yes' if probe.available else 'no'}"
        f" - tools: {len(probe.tools)}"
        f" - evidence: {probe.evidence.source}/{probe.evidence.method}[/]"
    )


def asar(
    archive: Annotated[Path, typer.Argument(help="Path to an .asar archive")],
    extract: Annotated[
        str | None,
        typer.Option(
            "--extract",
            help="In-archive entry to extract (written to the current directory)",
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the listing as JSON")
    ] = False,
) -> None:
    """List an Electron ASAR archive; optionally extract one entry (offline)."""
    try:
        listing = list_archive(archive)
        extracted = extract_file(archive, extract) if extract else None
    except AnalysisError as exc:
        _fail(str(exc))
    if extracted is not None:
        # Basename only: an in-archive path never becomes a host path.
        destination = Path(extracted.path.replace("\\", "/")).name
        Path(destination).write_bytes(extracted.data)
        console.print(
            f"[dim]extracted {escape(extracted.path)} -> {escape(destination)}"
            f" ({len(extracted.data)} bytes, sha256 {extracted.sha256})[/]"
        )
    if json_output:
        payload = listing.to_dict()
        if extracted is not None:
            payload["extract"] = extracted.to_dict()
        _print_json(payload)
        return
    table = Table(title=f"ASAR {escape(str(archive))}")
    table.add_column("Path")
    table.add_column("Size", justify="right")
    table.add_column("Offset", justify="right")
    for entry in listing.files:
        table.add_row(
            escape(entry.path),
            str(entry.size),
            str(entry.offset) if entry.offset is not None else "-",
        )
    console.print(table)
    console.print(
        f"[dim]files: {listing.file_count} - dirs: {listing.dir_count}"
        f" - bytes: {listing.total_bytes}"
        f" - truncated: {'yes' if listing.truncated else 'no'}"
        f" - apps: {', '.join(listing.top_level_apps) or '-'}"
        f" - evidence: {listing.evidence.source}/{listing.evidence.method}[/]"
    )
    if listing.truncated:
        console.print(
            f"[yellow]warning:[/] listing truncated; extract cap is "
            f"{MAX_EXTRACT_BYTES} bytes per entry"
        )
@web_app.command("capture")
def capture(
    har: Annotated[Path, typer.Argument(help="Path to a HAR (HTTP Archive) file")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the capture summary as JSON")
    ] = False,
) -> None:
    """Summarise a HAR capture offline: entries, times, types, hosts, gRPC."""
    try:
        summary = load_har(har)
    except AnalysisError as exc:
        _fail(str(exc))
    if json_output:
        _print_json(summary.to_dict())
        return
    table = Table(title=f"HAR {escape(str(har))}")
    table.add_column("Method")
    table.add_column("Status", justify="right")
    table.add_column("ms", justify="right")
    table.add_column("Type")
    table.add_column("gRPC")
    table.add_column("Url")
    for row in summary.rows:
        table.add_row(
            escape(row.method),
            str(row.status),
            f"{row.time_ms:g}",
            escape(row.content_type or "-"),
            "yes" if row.grpc else "-",
            escape(row.url),
        )
    console.print(table)
    console.print(
        f"[dim]entries: {summary.entry_count}"
        f" - total ms: {summary.total_time_ms:g}"
        f" - grpc: {summary.grpc_count}"
        f" - hosts: {', '.join(summary.hosts) or '-'}"
        f" - truncated: {'yes' if summary.truncated else 'no'}"
        f" - evidence: {summary.evidence.source}/{summary.evidence.method}[/]"
    )
    if summary.truncated:
        console.print(
            "[yellow]warning:[/] capture truncated by listing bounds "
            "(rows/types/hosts caps)"
        )


@web_app.command("proto")
def proto(
    body: Annotated[Path, typer.Argument(help="Path to a protobuf message body")],
    grpc: Annotated[
        bool,
        typer.Option("--grpc", help="Strip a leading 5-byte gRPC frame prefix first"),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the field tree as JSON")
    ] = False,
) -> None:
    """Decode a protobuf wire-format body into a structure-only field tree."""
    try:
        data = load_proto_bytes(body)
        result = decode_message(data, strip_grpc=grpc)
    except AnalysisError as exc:
        _fail(str(exc))
    if json_output:
        _print_json(result.to_dict())
        return
    table = Table(title=f"protobuf wire {escape(str(body))}")
    table.add_column("Field", justify="right")
    table.add_column("Wire")
    table.add_column("Kind")
    table.add_column("Depth", justify="right")
    table.add_column("Value")
    for item in result.fields:
        table.add_row(
            str(item.field_number),
            str(item.wire_type),
            escape(item.kind),
            str(item.depth),
            escape(_proto_value_text(item.value)),
        )
    console.print(table)
    if result.grpc_frame is not None:
        console.print(
            f"[dim]grpc frame: stripped ({result.grpc_frame.message_length} "
            "byte message)[/]"
        )
    for warning in result.warnings:
        _err_console.print(f"[yellow]warning:[/] {escape(warning)}")
    evidence = result.evidence
    if evidence is None:
        console.print("[dim]fields: no evidence record attached[/]")
        return
    console.print(
        f"[dim]fields: {result.field_count}"
        f" - depth: {result.depth_reached}"
        f" - evidence: {evidence.source}/{evidence.method}"
        f"/{evidence.confidence.value} (structure only, no .proto schema)[/]"
    )


def _proto_value_text(value: object) -> str:
    """Render one decoded field value for the table (bounded, flat)."""
    if isinstance(value, tuple):
        return f"<{len(value)} nested field(s)>"
    return str(value)


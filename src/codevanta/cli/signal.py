"""CODEVANTA signal commands: ``codevanta signal ...`` and ``codevanta dtb``.

``signal sr`` summarizes a sigrok ``.sr`` session archive, ``signal uart``
decodes a raw logic-0/1 capture as UART, and ``signal decode`` shells out to
sigrok-cli (skip-gated: absent tool, typed failure, exit 2). ``dtb`` parses
a flattened devicetree blob and is deliberately a top-level command, because
firmware people type ``codevanta dtb board.dtb`` more often than any other
lane command.

Every command prints a rich table of what was decoded, a dim totals footer,
every surprise as a ``warning:`` line and an ``evidence:`` footer naming the
lane source and confidence; ``--json`` prints the unchanged ``to_dict()``
payload.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.fdt import parse_dtb_file
from codevanta.analysis.sigrok_cli_wrap import decode_with_sigrok
from codevanta.analysis.sigrok_sr import summarize_session
from codevanta.analysis.uart_decode import (
    DEFAULT_BAUD,
    DEFAULT_DATA_BITS,
    DEFAULT_PARITY,
    DEFAULT_STOP_BITS,
    PARITIES,
    STOP_BITS_CHOICES,
    decode_uart_file,
)
from codevanta.core.report import AnalysisError

app = typer.Typer(help="Signal/firmware lane: sigrok sessions, UART captures, devicetrees")
signal_app = typer.Typer(help="Logic-capture inspection (sigrok sessions and raw UART)")
console = Console()

# One mount point for everything in this module: the nested "signal" typer
# serves `codevanta signal sr|uart|decode`, while commands defined on ``app``
# itself (dtb) land at the top level when main.py mounts this app unnamed.
app.add_typer(signal_app, name="signal")


def _fail(message: str, code: int) -> NoReturn:
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


def _print_warnings(warnings: list[str]) -> None:
    """Print every warning as its own ``warning:`` line."""
    for warning in warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@signal_app.command("sr")
def sr(
    file: Annotated[str, typer.Argument(help="Path to a sigrok .sr session archive")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit SrSessionSummary.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Summarize one sigrok .sr session: version, rate, channels, logic files."""
    try:
        result = summarize_session(file)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]sigrok session[/] {escape(str(file))} · version: {escape(str(result.version))}"
        f" · samplerate: {result.samplerate_hz if result.samplerate_hz else '?'} Hz"
        f" · device: {escape(result.device or '?')}"
    )
    table = Table(title="Logic files")
    table.add_column("Member", style="cyan")
    table.add_column("Bytes", justify="right")
    for logic in result.logic_files:
        table.add_row(escape(logic.name), str(logic.size_bytes))
    console.print(table)
    channel_table = Table(title="Channels")
    channel_table.add_column("Index", justify="right")
    channel_table.add_column("Name", style="cyan")
    for channel in result.channels:
        channel_table.add_row(str(channel.index), escape(channel.name))
    console.print(channel_table)
    if result.annotations_count is not None:
        console.print(f"[dim]annotations: {result.annotations_count}[/]")
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@signal_app.command("uart")
def uart(
    rawfile: Annotated[
        str, typer.Argument(help="Raw capture file: one byte per logic-0/1 sample")
    ],
    samplerate: Annotated[int, typer.Option(help="Capture sample rate in Hz")],
    baud: Annotated[int, typer.Option(help="Line speed in baud")] = DEFAULT_BAUD,
    parity: Annotated[
        str, typer.Option(help="Parity: " + "|".join(PARITIES))
    ] = DEFAULT_PARITY,
    databits: Annotated[int, typer.Option(help="Data bits per frame: 7 or 8")] = DEFAULT_DATA_BITS,
    stopbits: Annotated[int, typer.Option(help="Stop bits: 1 or 2")] = DEFAULT_STOP_BITS,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit UartResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Decoder-lite UART decode: falling-edge sync, mid-point bit sampling.

    Honest limits: no baud auto-detection, no glitch filtering beyond
    mid-point confirmation; verdicts carry medium confidence. Garbage input
    yields few or zero bytes with warnings, never a crash. Malformed
    parameters (unknown parity, impossible samplerate/baud ratio) exit 2
    before the file is read.
    """
    if parity not in PARITIES:
        _fail(f"invalid parity {parity!r}; expected one of {', '.join(PARITIES)}", 2)
    if stopbits not in STOP_BITS_CHOICES:
        _fail(
            f"invalid stopbits {stopbits}; expected one of "
            f"{', '.join(map(str, STOP_BITS_CHOICES))}",
            2,
        )
    try:
        result = decode_uart_file(
            rawfile,
            samplerate_hz=samplerate,
            baud=baud,
            data_bits=databits,
            parity=parity,
            stop_bits=stopbits,
        )
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]UART decode[/] {escape(str(rawfile))}"
        f" · {result.config.data_bits}{result.config.parity[0].upper()}"
        f"{result.config.stop_bits} @ {result.config.baud} baud"
        f" · {len(result.bytes)} byte(s) decoded"
    )
    table = Table(title="Decoded bytes")
    table.add_column("#", justify="right")
    table.add_column("Value", justify="right")
    table.add_column("Char")
    table.add_column("Verdict")
    for item in result.bytes:
        char = chr(item.value) if 32 <= item.value < 127 else "-"
        verdict = "ok" if item.ok else f"ERROR: {item.error}"
        table.add_row(str(item.index), f"0x{item.value:02x}", char, verdict)
    console.print(table)
    console.print(
        f"[dim]frames: {result.frames_found} · ok: {result.ok_count}"
        f" · parity errors: {result.parity_errors}"
        f" · framing errors: {result.framing_errors}"
        f" · samples scanned: {result.samples_scanned}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@signal_app.command("decode")
def decode(
    file: Annotated[str, typer.Argument(help="Capture file for sigrok-cli to decode")],
    decoder: Annotated[str, typer.Option(help="sigrok protocol decoder name, e.g. uart")],
    out_dir: Annotated[
        str | None, typer.Option(help="Directory for the raw sigrok-cli transcript")
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit SigrokDecodeResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Decode a capture with a real sigrok-cli protocol decoder (skip-gated).

    Requires sigrok-cli on PATH; without it this exits 2 with the install
    hint instead of pretending. Every annotation row sigrok-cli printed is
    listed; ``--out-dir`` preserves the raw transcript alongside.
    """
    try:
        result = decode_with_sigrok(file, decoder, out_dir=out_dir)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]sigrok decode[/] {escape(str(file))} · decoder: {escape(decoder)}"
        f" · {len(result.records)} record(s)"
    )
    table = Table(title="Annotations")
    table.add_column("Decoder", style="cyan")
    table.add_column("Samples")
    table.add_column("Annotation")
    for record in result.records:
        samples = (
            f"{record.start_sample}-{record.end_sample}"
            if record.start_sample is not None
            else "-"
        )
        table.add_row(escape(record.decoder), samples, escape(record.text))
    console.print(table)
    if result.transcript_path:
        console.print(f"[dim]transcript: {escape(result.transcript_path)}[/]")
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("dtb")
def dtb(
    file: Annotated[str, typer.Argument(help="Flattened devicetree (.dtb) blob")],
    node: Annotated[
        str | None,
        typer.Option(help="Top-level node whose properties are kept (default: root)"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit DtbSummary.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Parse a flattened devicetree: header, reservations, top-level nodes.

    The walk is deliberately shallow: the root, the top-level node names and
    the properties of one chosen node (``--node``, default root), values
    truncated to 64 bytes.
    """
    try:
        result = parse_dtb_file(file, node=node)
    except AnalysisError as exc:
        _fail(str(exc), 2)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]devicetree[/] {escape(str(file))} · v{result.version}"
        f" (compat {result.last_comp_version})"
        f" · {result.total_size} bytes · boot cpuid: {result.boot_cpuid_phys}"
    )
    console.print(f"[dim]nodes: {', '.join(result.nodes) if result.nodes else '(none)'}[/]")
    prop_table = Table(title=f"Properties of {escape(result.chosen_node or 'root')}")
    prop_table.add_column("Name", style="cyan")
    prop_table.add_column("Length", justify="right")
    prop_table.add_column("Value (ascii)")
    prop_table.add_column("Truncated")
    for prop in result.properties:
        prop_table.add_row(
            escape(prop.name),
            str(prop.length),
            escape("".join(chr(b) if 32 <= b < 127 else "." for b in prop.value)),
            "yes" if prop.truncated else "no",
        )
    console.print(prop_table)
    if result.reservations:
        res_table = Table(title="Memory reservations")
        res_table.add_column("Address")
        res_table.add_column("Size", justify="right")
        for reservation in result.reservations:
            res_table.add_row(f"0x{reservation.address:x}", f"0x{reservation.size:x}")
        console.print(res_table)
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())




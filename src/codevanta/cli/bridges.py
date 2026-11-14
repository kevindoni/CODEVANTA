"""CODEVANTA bridges commands: capability report and the depth-bridge lanes.

Five small Typer apps exported as one :data:`bridges_apps` tuple so
:mod:`codevanta.cli.main` registers the whole lane with a single loop:

* ``codevanta bridges [--json]`` -- the capability report
  (:func:`codevanta.analysis.bridge.bridges_report`), one row per bridge.
* ``codevanta firmware extract <file> --out-dir DIR [--tool binwalk|unblob]
  [--json]`` -- firmware extraction depth bridge.
* ``codevanta pcap fields <file> --fields a,b [--filter EXPR] [--limit N]
  [--json]`` -- tshark field extraction depth bridge.
* ``codevanta wasm validate <file> [--json]`` and ``codevanta wasm disasm
  <file> [--json]`` -- wabt depth bridge.
* ``codevanta objdump <file> [--arch A] [--json]`` -- objdump depth bridge.

Every command maps the lane's typed
:class:`~codevanta.core.report.AnalysisError` to ``exit 2`` (a missing tool
is a report, not a crash), prints warnings as ``warning:`` lines and an
``evidence:`` footer; ``--json`` prints the unchanged ``to_dict()`` payload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis import binwalk_bridge, objdump_bridge, tshark_bridge, wabt_bridge
from codevanta.analysis.bridge import BridgeCapability, bridges_report
from codevanta.core.report import AnalysisError

#: The whole lane, registered by one loop in ``cli/main.py`` (deterministic order).
bridges_apps: tuple[tuple[str, typer.Typer], ...] = ()

app = typer.Typer(
    invoke_without_command=True,
    # Single-command sub-app: FILE and --json may appear in any order.
    context_settings={"allow_interspersed_args": True},
    help="External tool bridges: capability report plus depth-bridge lanes",
)
firmware_app = typer.Typer(help="Firmware extraction over binwalk/unblob (requires the tool on PATH)")
pcap_app = typer.Typer(help="Packet field extraction over tshark (requires tshark on PATH)")
wasm_app = typer.Typer(help="WebAssembly inspection over wabt (requires wasm-validate/wasm-objdump)")
objdump_app = typer.Typer(
    invoke_without_command=True,
    context_settings={"allow_interspersed_args": True},
    help="Disassemble over GNU objdump (requires objdump on PATH)",
)
console = Console()


def _fail(message: str) -> NoReturn:
    """Print an error and exit with code 2 (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=2) from None


def _run(call: Any, *args: Any, **kwargs: Any) -> Any:
    """Call one lane wrapper, mapping every typed failure to ``exit 2``."""
    try:
        return call(*args, **kwargs)
    except AnalysisError as exc:
        _fail(str(exc))


def _evidence_footer(evidence: dict[str, Any]) -> None:
    """Print the shared ``evidence:`` footer line."""
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source')))}"
        f" via {escape(str(evidence.get('method')))}"
        f" · confidence: {escape(str(evidence.get('confidence')))}[/]"
    )


def _print_warnings(warnings: list[str]) -> None:
    """Print each warning as a ``warning:`` line."""
    for warning in warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


def _json_payload(payload: dict[str, Any]) -> None:
    """Print one lane payload as JSON."""
    console.print_json(json.dumps(payload))
def _print_capability(capability: BridgeCapability) -> None:
    """Print one capability row as a compact line (human output)."""
    if capability.available:
        console.print(
            f"  [green]available[/] {escape(capability.tool)}"
            + (f" · version {escape(capability.version)}" if capability.version else "")
        )
        if capability.reason:
            console.print(f"    [dim]{escape(capability.reason)}[/]")
        return
    console.print(f"  [red]missing[/]   {escape(capability.tool)}")
    if capability.reason:
        console.print(f"    [dim]{escape(capability.reason)}[/]")


@app.callback(invoke_without_command=True)
def bridges(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the capability report as JSON instead of lines"),
    ] = False,
) -> None:
    """Report which depth-bridge tools this machine could use.

    Probes binwalk, unblob, tshark, wabt (wasm-validate + wasm-objdump),
    objdump, sigrok-cli, adb, gdb and z3 -- each with one bounded version
    call -- and prints an honest available/missing verdict per tool. The
    report never fails a machine for lacking tools; only an internal probe
    error would map to ``exit 2``.
    """
    capabilities = _run(bridges_report)
    payload = {
        "bridges": [capability.to_dict() for capability in capabilities],
        "count": len(capabilities),
        "available": sum(1 for capability in capabilities if capability.available),
    }
    if json_output:
        _json_payload(payload)
        return
    console.print("[bold]CODEVANTA depth bridges[/]")
    for capability in capabilities:
        _print_capability(capability)
    console.print(
        f"[dim]{payload['available']}/{payload['count']} bridges available · "
        "wrappers skip-gate on these probes; pure-Python fallbacks run regardless[/]"
    )


@firmware_app.command("extract")
def firmware_extract(
    file: Annotated[Path, typer.Argument(help="Path to the firmware image")],
    out_dir: Annotated[
        Path, typer.Option("--out-dir", help="Directory to extract into (created when missing)")
    ],
    tool: Annotated[
        str,
        typer.Option("--tool", help="Extractor to drive: binwalk (default) or unblob"),
    ] = "binwalk",
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit FirmwareExtractResult.to_dict() as JSON")
    ] = False,
) -> None:
    """Extract a firmware image with binwalk or unblob and report the findings.

    Skip-gated: without the chosen tool on PATH the command exits 2 with the
    install hint and the offline `codevanta binmeta <file>` fallback. The
    report keeps the tool's bounded transcript parse and a shallow scan of
    the extraction directory it produced.
    """
    result = _run(binwalk_bridge.firmware_extract, file, out_dir, tool=tool)
    if json_output:
        _json_payload(result.to_dict())
        return
    console.print(f"[bold]firmware extract ({escape(result.tool)})[/]")
    _print_warnings(result.warnings)
    table = Table(title="Reported entries")
    table.add_column("Offset", justify="right")
    table.add_column("Kind")
    table.add_column("Size", justify="right")
    table.add_column("Path")
    for entry in result.entries:
        table.add_row(
            f"0x{entry.offset:x}" if entry.offset is not None else "-",
            escape(entry.kind),
            str(entry.size) if entry.size is not None else "-",
            escape(entry.path) if entry.path else "-",
        )
    console.print(table)
    if not result.entries:
        console.print("[yellow]no extraction entries reported[/]")
    shown = ", ".join(result.tree[:8]) if result.tree else "(nothing written)"
    console.print(
        f"[dim]extracted tree: {escape(shown)}"
        f"{' …' if result.tree_truncated else ''} · {len(result.tree)} path(s)[/]"
    )
    _evidence_footer(result.evidence.to_dict())


@pcap_app.command("fields")
def pcap_fields(
    file: Annotated[Path, typer.Argument(help="Path to the pcap/pcapng capture")],
    fields: Annotated[str, typer.Option("--fields", help="Comma-separated tshark -e field names")],
    display_filter: Annotated[
        str | None, typer.Option("--filter", help="tshark display filter (-Y) expression")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Maximum packets to decode (1..100)")
    ] = tshark_bridge.DEFAULT_PACKET_LIMIT,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit PcapFieldsResult.to_dict() as JSON")
    ] = False,
) -> None:
    """Extract protocol fields from a capture with tshark and tabulate them.

    Skip-gated: without tshark on PATH the command exits 2 with the install
    hint and the offline `codevanta binmeta <file>` structural fallback.
    """
    result = _run(
        tshark_bridge.pcap_fields,
        file,
        fields,
        display_filter=display_filter,
        packet_limit=limit,
    )
    if json_output:
        _json_payload(result.to_dict())
        return
    console.print(f"[bold]pcap fields ({escape(', '.join(result.fields))})[/]")
    _print_warnings(result.warnings)
    table = Table(title=f"First {len(result.rows)} packet(s)")
    for name in result.fields:
        table.add_column(name)
    for row in result.rows:
        table.add_row(
            *(escape(row.fields.get(name) or "-") for name in result.fields)
        )
    console.print(table)
    if not result.rows:
        console.print("[yellow]no packets matched[/]")
    footer = f"[dim]{len(result.rows)} row(s) · packet limit {result.packet_limit}"
    if result.display_filter:
        footer += f" · filter: {escape(result.display_filter)}"
    console.print(footer + "[/]")
    _evidence_footer(result.evidence.to_dict())

@wasm_app.command("validate")
def wasm_validate(
    file: Annotated[Path, typer.Argument(help="Path to the .wasm module")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit WasmValidateResult.to_dict() as JSON")
    ] = False,
) -> None:
    """Validate a WebAssembly module with wasm-validate (verdict, not crash).

    A module that fails validation is a successful tool run: the verdict
    prints as `invalid` with the parsed error lines. Skip-gated: without wabt
    on PATH the command exits 2 with the install hint.
    """
    result = _run(wabt_bridge.wasm_validate, file)
    if json_output:
        _json_payload(result.to_dict())
        return
    verdict = "[green]valid[/]" if result.valid else "[red]invalid[/]"
    console.print(f"[bold]wasm validate:[/] {verdict} · {escape(result.path)}")
    _print_warnings(result.warnings)
    for error in result.errors:
        console.print(f"[red]error:[/] {escape(error)}")
    _evidence_footer(result.evidence.to_dict())


@wasm_app.command("disasm")
def wasm_disasm(
    file: Annotated[Path, typer.Argument(help="Path to the .wasm module")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit WasmObjdumpResult.to_dict() as JSON")
    ] = False,
) -> None:
    """Disassemble a WebAssembly module with wasm-objdump (bounded 128 rows).

    Skip-gated: without wabt on PATH the command exits 2 with the install
    hint.
    """
    result = _run(wabt_bridge.wasm_objdump, file)
    if json_output:
        _json_payload(result.to_dict())
        return
    console.print(f"[bold]wasm disasm[/] · {escape(result.path)}")
    _print_warnings(result.warnings)
    if result.sections:
        sections = ", ".join(
            f"{section.name}({section.size:#x})" if section.size is not None else section.name
            for section in result.sections
        )
        console.print(f"[dim]sections: {escape(sections)}[/]")
    table = Table(title=f"First {len(result.instructions)} instruction(s)")
    table.add_column("Offset", justify="right")
    table.add_column("Bytes")
    table.add_column("Instruction")
    for instruction in result.instructions:
        table.add_row(
            f"0x{instruction.offset:x}",
            escape(instruction.raw_bytes),
            escape(instruction.text),
        )
    console.print(table)
    if not result.instructions:
        console.print("[yellow]no instructions decoded[/]")
    if result.truncated:
        console.print("[yellow]instruction list was truncated[/]")
    _evidence_footer(result.evidence.to_dict())


@objdump_app.callback(invoke_without_command=True)
def objdump(
    file: Annotated[Path, typer.Argument(help="Path to the binary to disassemble")],
    arch: Annotated[
        str | None, typer.Option("--arch", help="objdump -m architecture (e.g. i386:x86-64)")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit ObjdumpDisasmResult.to_dict() as JSON")
    ] = False,
) -> None:
    """Disassemble a binary with GNU objdump (bounded 512 rows).

    Skip-gated: without objdump on PATH the command exits 2 with the
    binutils install hint. Output is capped at 512 lines before parsing.
    """
    result = _run(objdump_bridge.objdump_disasm, file, arch=arch)
    if json_output:
        _json_payload(result.to_dict())
        return
    header = "[bold]objdump -d[/]"
    if result.arch:
        header += f" · arch {escape(result.arch)}"
    console.print(f"{header} · {escape(result.path)}")
    _print_warnings(result.warnings)
    table = Table(title=f"First {len(result.rows)} instruction(s)")
    table.add_column("Address", justify="right")
    table.add_column("Bytes")
    table.add_column("Instruction")
    for row in result.rows:
        text = row.mnemonic + (f" {row.operands}" if row.operands else "")
        table.add_row(f"0x{row.address:x}", escape(row.bytes), escape(text))
    console.print(table)
    if not result.rows:
        console.print("[yellow]no instructions decoded[/]")
    if result.truncated:
        console.print("[yellow]output was truncated[/]")
    _evidence_footer(result.evidence.to_dict())


#: Registered by one loop in ``cli/main.py``: ``codevanta bridges``,
#: ``codevanta firmware extract``, ``codevanta pcap fields``,
#: ``codevanta wasm validate|disasm`` and ``codevanta objdump``.
bridges_apps = (
    ("bridges", app),
    ("firmware", firmware_app),
    ("pcap", pcap_app),
    ("wasm", wasm_app),
    ("objdump", objdump_app),
)


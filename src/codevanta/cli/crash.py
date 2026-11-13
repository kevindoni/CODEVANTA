"""CODEVANTA crash-dump commands: ``codevanta crash core`` and ``crash ips``.

Two crash-dump families, one command each, both wired to the same contract as
the rest of the CLI: a table of what was decoded, a dim totals footer, every
surprise as a ``warning:`` line, an ``evidence:`` footer naming the source and
confidence, and ``--json`` for the unchanged ``to_dict()`` payload.

``crash core`` reads a Linux ELF core dump
(:func:`codevanta.analysis.crash_core.parse_core_dump`) and prints the faulting
thread's registers, the killing signal, the process identity and the mapped
modules. ``crash ips`` reads an Apple ``.ips`` crash report
(:func:`codevanta.analysis.apple_ips.parse_ips_report`, both generations) and
prints the faulting thread's stack frames plus the report metadata.

Neither command executes anything: a crash dump is dead data, and the only
thing these commands do with it is read it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.apple_ips import IpsSummary, parse_ips_report
from codevanta.analysis.crash_core import CoreDumpSummary, parse_core_dump
from codevanta.core.report import AnalysisError

app = typer.Typer(help="Crash-dump analysis: ELF core dumps and Apple .ips reports")
console = Console()

#: Human names for the signals a core dump's ``NT_SIGINFO``/``pr_cursig`` carries.
_SIGNAL_NAMES: dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    31: "SIGSYS",
}


def _fail(message: str, code: int) -> NoReturn:
    """Print an error and exit with ``code`` (mirrors the main CLI helper)."""
    console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(code=code) from None


def _signal_label(signal: int | None) -> str:
    """Return ``SIGSEGV (11)``-style label, or ``-`` when unknown."""
    if signal is None:
        return "-"
    name = _SIGNAL_NAMES.get(signal, "unknown")
    return f"{name} ({signal})"


def _run_core(path: Path) -> CoreDumpSummary:
    """Parse an ELF core dump, mapping every failure to ``exit 2``."""
    try:
        return parse_core_dump(path)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_ips(path: Path) -> IpsSummary:
    """Parse an Apple ``.ips`` report, mapping every failure to ``exit 2``."""
    try:
        return parse_ips_report(path)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _evidence_footer(evidence: dict[str, Any]) -> None:
    """Print the shared ``evidence:`` footer line."""
    console.print(
        f"[dim]evidence: {escape(str(evidence.get('source')))}"
        f" via {escape(str(evidence.get('method')))}"
        f" · confidence: {escape(str(evidence.get('confidence')))}[/]"
    )


def _print_core(summary: CoreDumpSummary) -> None:
    """Render a core-dump summary as register/module tables plus a footer."""
    console.print(
        f"[bold]ELF core dump[/] · arch: {escape(summary.arch)}"
        f" · signal: {_signal_label(summary.signal)} · pid: {summary.pid or '-'}"
        f" · comm: {escape(summary.comm or '-')}"
        f" · exe: {escape(summary.exe or '-')}"
    )
    if summary.registers:
        table = Table(title="Faulting thread registers")
        table.add_column("Register")
        table.add_column("Value", justify="right")
        for name, value in summary.registers.items():
            table.add_row(name, f"0x{value:x}")
        console.print(table)
    else:
        console.print("[yellow]no registers decoded from the core dump[/]")
    if summary.fault_addr is not None:
        console.print(f"[dim]fault address: 0x{summary.fault_addr:x}[/]")
    if summary.mapped_modules:
        modules = Table(title=f"Mapped modules ({len(summary.mapped_modules)})")
        modules.add_column("Start", justify="right")
        modules.add_column("End", justify="right")
        modules.add_column("Name")
        for module in summary.mapped_modules:
            modules.add_row(
                f"0x{module.start:x}", f"0x{module.end:x}", escape(module.name)
            )
        console.print(modules)
    console.print(
        f"[dim]threads: {summary.threads} · notes: {summary.notes_seen}"
        f" · fpregset: {'yes' if summary.fpregset_present else 'no'}"
        f" · truncated: {'yes' if summary.truncated else 'no'}[/]"
    )
    for warning in summary.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    _evidence_footer(summary.evidence.to_dict())


def _print_ips(summary: IpsSummary) -> None:
    """Render an ``.ips`` summary as a frame table plus a footer."""
    console.print(
        f"[bold]Apple .ips crash report ({escape(summary.format)} format)[/]"
        f" · product: {escape(summary.product or '-')}"
        f" · os: {escape(summary.os_version or '-')}"
        f" · time: {escape(summary.crash_time or '-')}"
    )
    console.print(
        f"exception: {escape(summary.exception_type or '-')}"
        f" · signal: {escape(summary.exception_signal or '-')}"
        f" · termination: {escape(summary.termination_reason or '-')}"
    )
    if summary.frames:
        table = Table(
            title=f"Faulting thread frames (thread {summary.faulting_thread})"
        )
        table.add_column("#", justify="right")
        table.add_column("Image")
        table.add_column("Offset", justify="right")
        table.add_column("Symbol")
        for frame in summary.frames:
            symbol = "-"
            if frame.symbol is not None:
                location = (
                    f" + {frame.symbol_location}"
                    if frame.symbol_location is not None
                    else ""
                )
                symbol = f"{frame.symbol}{location}"
            table.add_row(
                str(frame.index),
                escape(frame.image or "-"),
                "-" if frame.offset is None else f"0x{frame.offset:x}",
                escape(symbol),
            )
        console.print(table)
    else:
        console.print("[yellow]no faulting-thread frames decoded[/]")
    console.print(
        f"[dim]images: {len(summary.images)} · frames: {len(summary.frames)}"
        f" · truncated: {'yes' if summary.truncated else 'no'}[/]"
    )
    for warning in summary.warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")
    _evidence_footer(summary.evidence.to_dict())


@app.command("core")
def core(
    path: Annotated[Path, typer.Argument(help="Path to the ELF core dump")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit CoreDumpSummary.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Summarise a Linux ELF core dump: signal, registers, modules.

    The parse reads the ``PT_NOTE`` segments only: the faulting thread's
    ``rip``/``rsp``/``rbp`` (or the ``eip`` set on i386, ``pc``/``sp`` on
    aarch64), the killing signal and fault address from ``NT_SIGINFO``, process
    identity from ``NT_PRPSINFO``, and the mapped modules from ``NT_FILE`` --
    falling back to the ``PT_LOAD`` segments when the core carries no file
    table. A file that is not an ELF core dump, is big-endian, or is cut short
    exits 2 with a typed message; a file that parses with surprises keeps going
    and lists them as ``warning:`` lines. ``--json`` prints the summary
    unchanged.
    """
    summary = _run_core(path)
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    _print_core(summary)


@app.command("ips")
def ips(
    path: Annotated[Path, typer.Argument(help="Path to the Apple .ips crash report")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit IpsSummary.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Summarise an Apple .ips crash report (JSON and plist generations).

    The report's generation is detected from its shape -- a JSON dump header
    line (optionally preceded by the literal ``JSON dump header`` marker) means
    the modern format, a plist header line followed by XML means the legacy
    format. The render names the product, OS version and crash time, the
    exception type and signal, the termination reason, and one row per
    faulting-thread frame with its image, offset and symbol when the report was
    written with symbols. A file that matches neither generation exits 2.
    ``--json`` prints the summary unchanged.
    """
    summary = _run_ips(path)
    if json_output:
        console.print_json(json.dumps(summary.to_dict()))
        return
    _print_ips(summary)

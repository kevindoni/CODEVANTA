"""CODEVANTA mobile commands: ``codevanta mobile`` -- Android over adb.

Thirteen commands, one per lane wrapper: ``devices``, ``props <serial>``,
``packages <serial>``, ``processes <serial>``, ``install <serial> <apk>
[--yes]``, ``screencap <serial> <out>``, ``bugreport <serial> <outdir>``,
``logcat <serial> [--pid N] [--count N]``, ``pull <serial> <device> <out>``,
``push <serial> <local> <device>``, ``start <serial> <package>``,
``stop <serial> <package>`` and ``setting <serial> <namespace> <key>``.
Each prints the decoded rows as a table with a dim totals footer, every
surprise as a ``warning:`` line and an ``evidence:`` footer naming the adb
source and confidence; ``--json`` prints the unchanged ``to_dict()`` payload.

Nothing here hides adb's absence: a machine without adb on ``PATH`` gets the
typed ``adb is not on PATH`` failure with the install hint and exit code 2,
exactly like the gdb lane on a machine without gdb. ``install`` is the only
mutating command and refuses to run without ``--yes``.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from codevanta.analysis.adb import (
    AdbBugreportResult,
    AdbDevicesResult,
    AdbFileTransferResult,
    AdbInstallResult,
    AdbLogcatResult,
    AdbPackagesResult,
    AdbProcessesResult,
    AdbPropsResult,
    AdbScreencapResult,
    AdbSettingResult,
    AdbStartResult,
    AdbStopResult,
    bugreport,
    inspect_device,
    install_apk,
    list_devices,
    list_packages,
    list_processes,
    pull_file,
    push_file,
    read_logcat,
    read_setting,
    screencap,
    start_app,
    stop_app,
)
from codevanta.core.report import AnalysisError

app = typer.Typer(help="Android device inspection over adb (requires adb on PATH)")
console = Console()


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


def _run_devices() -> AdbDevicesResult:
    """List devices, mapping every failure to ``exit 2``."""
    try:
        return list_devices()
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_props(serial: str) -> AdbPropsResult:
    """Read build identity, mapping every failure to ``exit 2``."""
    try:
        return inspect_device(serial)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_packages(serial: str) -> AdbPackagesResult:
    """List third-party packages, mapping every failure to ``exit 2``."""
    try:
        return list_packages(serial)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_processes(serial: str) -> AdbProcessesResult:
    """List processes, mapping every failure to ``exit 2``."""
    try:
        return list_processes(serial)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_install(serial: str, apk: str, *, confirm: bool) -> AdbInstallResult:
    """Install an APK, mapping every failure (including refusal) to ``exit 2``."""
    try:
        return install_apk(serial, apk, confirm=confirm)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_screencap(serial: str, out: str) -> AdbScreencapResult:
    """Capture a screenshot, mapping every failure to ``exit 2``."""
    try:
        return screencap(serial, out)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_bugreport(serial: str, outdir: str) -> AdbBugreportResult:
    """Write a bugreport zip, mapping every failure to ``exit 2``."""
    try:
        return bugreport(serial, outdir)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _print_warnings(warnings: list[str]) -> None:
    """Print each warning as a ``warning:`` line."""
    for warning in warnings:
        console.print(f"[yellow]warning:[/] {escape(warning)}")


@app.command("devices")
def devices(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbDevicesResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """List attached devices and emulators: serial, state, kind, model.

    Reads ``adb devices -l`` through the lane parser. A machine without adb
    exits 2 with the typed ``adb is not on PATH`` message and the install hint.
    """
    result = _run_devices()
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"ADB devices ({len(result.devices)})")
    table.add_column("Serial")
    table.add_column("State")
    table.add_column("Kind")
    table.add_column("Model")
    for device in result.devices:
        table.add_row(
            escape(device.serial),
            escape(device.state),
            escape(device.kind),
            escape(device.model or "-"),
        )
    console.print(table)
    if not result.devices:
        console.print("[yellow]no devices attached[/]")
    console.print(
        f"[dim]devices: {len(result.devices)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("props")
def props(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbPropsResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Print the whitelisted build identity of one device.

    Reads ``adb -s <serial> shell getprop`` and keeps ``ro.build.version.*``,
    ``ro.product.*`` and ``ro.build.fingerprint``; everything else is dropped by
    the parser's whitelist.
    """
    result = _run_props(serial)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"Build identity ({escape(serial)})")
    table.add_column("Property")
    table.add_column("Value")
    for key, value in result.props.items():
        table.add_row(escape(key), escape(value))
    console.print(table)
    if not result.props:
        console.print("[yellow]no whitelisted properties decoded[/]")
    console.print(
        f"[dim]properties: {len(result.props)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("packages")
def packages(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbPackagesResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """List the third-party packages installed on one device.

    Reads ``adb -s <serial> shell pm list packages -3``; rows are name and,
    when the transcript carries them, the installing ``base.apk`` path.
    """
    result = _run_packages(serial)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"Third-party packages ({escape(serial)})")
    table.add_column("Package")
    table.add_column("APK path")
    for package in result.packages:
        table.add_row(escape(package.name), escape(package.path or "-"))
    console.print(table)
    if not result.packages:
        console.print("[yellow]no third-party packages listed[/]")
    console.print(
        f"[dim]packages: {len(result.packages)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("processes")
def processes(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbProcessesResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """List the processes running on one device.

    Reads ``adb -s <serial> shell ps -A``; rows are user, pid, ppid, rss (KiB),
    the one-letter state and the process name.
    """
    result = _run_processes(serial)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"Processes ({escape(serial)})")
    table.add_column("User")
    table.add_column("PID", justify="right")
    table.add_column("PPID", justify="right")
    table.add_column("RSS", justify="right")
    table.add_column("State")
    table.add_column("Name")
    for process in result.processes:
        table.add_row(
            escape(process.user),
            str(process.pid),
            "-" if process.ppid is None else str(process.ppid),
            "-" if process.rss is None else str(process.rss),
            escape(process.state or "-"),
            escape(process.name),
        )
    console.print(table)
    if not result.processes:
        console.print("[yellow]no processes decoded[/]")
    console.print(
        f"[dim]processes: {len(result.processes)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("install")
def install(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    apk: Annotated[str, typer.Argument(help="Path to the APK on this host")],
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the install (required; adb install mutates the device)"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbInstallResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Install an APK on one device -- host sha256 + size recorded first.

    Requires ``--yes``: this is the lane's one mutating command. Without it the
    command exits 2 with a typed refusal before adb is invoked. The recorded
    digest names exactly which bytes the device was asked to accept.
    """
    result = _run_install(serial, apk, confirm=yes)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Installed[/] {escape(result.apk)} on {escape(result.serial)}"
        f" · sha256: {result.sha256} · size: {result.size} bytes"
    )
    if result.output:
        console.print(f"[dim]adb: {escape(result.output)}[/]")
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("push")
def push(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    local: Annotated[str, typer.Argument(help="File path on this host")],
    device_path: Annotated[str, typer.Argument(help="Destination path on the device")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbFileTransferResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Push one host file to the device; the sha256 is recorded before adb runs.

    Transfers over 512 MiB are refused pre-flight with a typed error.
    """
    result = _run_push(serial, local, device_path)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Pushed[/] {escape(result.host_path)} -> {escape(result.device_path)}"
        f" · size: {result.size} bytes · sha256: {result.sha256}"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("start")
def start(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    package: Annotated[str, typer.Argument(help="Package to launch, e.g. com.example.app")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbStartResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Launch an app via ``am start -W`` and print Status/LaunchState/TotalTime."""
    result = _run_start(serial, package)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Start[/] {escape(result.package)} on {escape(result.serial)}"
        f" · status: {escape(result.status or '-')} · launch: {escape(result.launch_state or '-')}"
        f" · total: {result.total_time_ms if result.total_time_ms is not None else '-'} ms"
    )
    if result.error:
        console.print(f"[yellow]error:[/] {escape(result.error)}")
    if result.component:
        console.print(f"[dim]component: {escape(result.component)}[/]")
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("stop")
def stop(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    package: Annotated[str, typer.Argument(help="Package to force-stop")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbStopResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Force-stop an app via ``am force-stop``."""
    result = _run_stop(serial, package)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Stop[/] {escape(result.package)} on {escape(result.serial)}"
        f" · stopped: {'yes' if result.stopped else 'no'}"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("setting")
def setting(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    namespace: Annotated[
        str, typer.Argument(help="Settings table: system, secure or global")
    ],
    key: Annotated[str, typer.Argument(help="Setting key, e.g. screen_brightness")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbSettingResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Read one setting via ``settings get <namespace> <key>`` (an unset value prints null)."""
    result = _run_setting(serial, namespace, key)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Setting[/] {escape(result.namespace)}/{escape(result.key)}"
        f" on {escape(result.serial)} = {escape(result.value if result.value is not None else 'null')}"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


def _run_logcat(serial: str, *, pid: int | None, count: int) -> AdbLogcatResult:
    """Dump recent log rows, mapping every failure to ``exit 2``."""
    try:
        return read_logcat(serial, pid=pid, count=count)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_pull(serial: str, device_path: str, out: str) -> AdbFileTransferResult:
    """Pull a file, mapping every failure to ``exit 2``."""
    try:
        return pull_file(serial, device_path, out)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_push(serial: str, local: str, device_path: str) -> AdbFileTransferResult:
    """Push a file, mapping every failure to ``exit 2``."""
    try:
        return push_file(serial, local, device_path)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_start(serial: str, package: str) -> AdbStartResult:
    """Launch an app, mapping every failure to ``exit 2``."""
    try:
        return start_app(serial, package)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_stop(serial: str, package: str) -> AdbStopResult:
    """Force-stop an app, mapping every failure to ``exit 2``."""
    try:
        return stop_app(serial, package)
    except AnalysisError as exc:
        _fail(str(exc), 2)


def _run_setting(serial: str, namespace: str, key: str) -> AdbSettingResult:
    """Read one setting, mapping every failure to ``exit 2``."""
    try:
        return read_setting(serial, namespace, key)
    except AnalysisError as exc:
        _fail(str(exc), 2)


@app.command("screencap")
def screencap_command(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    out: Annotated[str, typer.Argument(help="Path for the PNG capture on this host")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbScreencapResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Capture the device screen as a PNG via ``exec-out screencap -p``.

    The capture is written, hashed and checked for the PNG magic; a non-PNG
    capture is written anyway and flagged as a ``warning:`` line.
    """
    result = _run_screencap(serial, out)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Screencap[/] {escape(result.serial)} -> {escape(result.path)}"
        f" · size: {result.size} bytes · sha256: {result.sha256}"
        f" · png: {'yes' if result.is_png else 'no'}"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("bugreport")
def bugreport_command(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    outdir: Annotated[str, typer.Argument(help="Directory for the bugreport zip")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbBugreportResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Write one ``adb bugreport`` zip into a directory on this host.

    The zip lands at ``<outdir>/codevanta-bugreport-<serial>.zip``. A full
    bugreport on real hardware often outlasts the lane's 20 s default budget;
    use the Python API's ``timeout`` parameter for those devices.
    """
    result = _run_bugreport(serial, outdir)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Bugreport[/] {escape(result.serial)} -> {escape(result.path)}"
        f" · size: {result.size} bytes"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("logcat")
def logcat(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    pid: Annotated[
        int | None,
        typer.Option("--pid", help="Only rows from this PID (adb --pid=N)"),
    ] = None,
    count: Annotated[
        int,
        typer.Option("--count", help="How many recent rows to ask adb for"),
    ] = 50,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbLogcatResult.to_dict() instead of a table"),
    ] = False,
) -> None:
    """Dump recent device log rows via ``adb logcat -d -t <count>``.

    Rows decode as priority, tag, pid and message; unparsable rows become
    ``warning:`` lines. The parser keeps at most 200 rows however large the
    ``--count`` ask was.
    """
    result = _run_logcat(serial, pid=pid, count=count)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    table = Table(title=f"Logcat ({escape(serial)})")
    table.add_column("Priority")
    table.add_column("Tag")
    table.add_column("PID", justify="right")
    table.add_column("Message")
    for line in result.lines:
        table.add_row(
            escape(line.priority),
            escape(line.tag),
            str(line.pid),
            escape(line.message),
        )
    console.print(table)
    if not result.lines:
        console.print("[yellow]no logcat rows decoded[/]")
    console.print(
        f"[dim]rows: {len(result.lines)}"
        f" · truncated: {'yes' if result.truncated else 'no'}[/]"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())


@app.command("pull")
def pull(
    serial: Annotated[str, typer.Argument(help="Device serial (see `mobile devices`)")],
    device_path: Annotated[str, typer.Argument(help="File path on the device")],
    out: Annotated[str, typer.Argument(help="Destination path on this host")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit AdbFileTransferResult.to_dict() instead of a summary"),
    ] = False,
) -> None:
    """Pull one file from the device; the host-side sha256 is recorded.

    Transfers over 512 MiB are refused with a typed error.
    """
    result = _run_pull(serial, device_path, out)
    if json_output:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(
        f"[bold]Pulled[/] {escape(result.device_path)} -> {escape(result.host_path)}"
        f" · size: {result.size} bytes · sha256: {result.sha256}"
    )
    _print_warnings(result.warnings)
    _evidence_footer(result.evidence.to_dict())



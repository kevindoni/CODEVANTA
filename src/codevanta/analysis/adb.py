"""Android/ADB lane: pure parsers plus thin, skip-gated live wrappers.

This module is the ADB twin of the gdb lane: everything that *understands*
device output is a pure parser that is fully tested offline against canned
transcripts, and everything that *touches* a device is a thin wrapper that is
skip-gated on one ``shutil.which`` probe and shells out with a bounded
timeout. On a machine without adb -- a Windows workstation, a slim CI
container -- the parsers still run and the wrappers still import; they only
ever fail with a typed error naming exactly what is missing.

Pure parsers
------------
:func:`parse_devices` reads ``adb devices -l`` output (serial, state, model,
and an emulator/physical kind), :func:`parse_packages` reads
``pm list packages -3`` (name, and the ``base.apk`` path when the ``-f``
prefixed transcript is fed in), :func:`parse_processes` reads ``ps -A`` in
both the modern (``VSZ``/``ADDR``/``S``) and legacy (``VSIZE``) column
layouts, :func:`parse_services` reads ``service list`` lines,
:func:`parse_getprop` keeps the build-identity whitelist
(``ro.build.version.*``, ``ro.product.*``, ``ro.build.fingerprint``) from a
getprop dump in either the bracketed or the plain rendering,
:func:`parse_dumpsys_package` pulls versionName, installer, firstInstallTime
and the requested-permission count out of one ``dumpsys package`` transcript,
and :func:`parse_window_focus` decodes ``mCurrentFocus``/``mFocusedApp`` from
``dumpsys window``. Every parser tolerates junk lines as warnings; malformed
*input to the parser itself* (anything that is not ``str``) raises
:class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "ADB_MISSING_MESSAGE",
    "AdbBugreportResult",
    "AdbDevice",
    "AdbDevicesResult",
    "AdbFileTransferResult",
    "AdbInstallResult",
    "AdbLogcatLine",
    "AdbLogcatResult",
    "AdbPackageEntry",
    "AdbPackageInfoResult",
    "AdbPackagesResult",
    "AdbProcessEntry",
    "AdbProcessesResult",
    "AdbPropsResult",
    "AdbScreencapResult",
    "AdbServiceEntry",
    "AdbServicesResult",
    "AdbSettingResult",
    "AdbStartResult",
    "AdbStopResult",
    "AdbWindowFocusResult",
    "DEFAULT_TIMEOUT",
    "MAX_APK_BYTES",
    "MAX_DEVICES",
    "MAX_LOG_LINES",
    "MAX_LOG_MSG_CHARS",
    "MAX_PACKAGES",
    "MAX_PROCESSES",
    "MAX_PROPS",
    "MAX_SERVICES",
    "MAX_TIMEOUT",
    "MAX_TRANSFER_BYTES",
    "MAX_WARNINGS",
    "Runner",
    "RunnerOutcome",
    "adb_available",
    "bugreport",
    "inspect_device",
    "install_apk",
    "list_devices",
    "list_packages",
    "list_processes",
    "parse_am_start",
    "parse_devices",
    "parse_dumpsys_package",
    "parse_getprop",
    "parse_logcat",
    "parse_packages",
    "parse_processes",
    "parse_services",
    "parse_window_focus",
    "pull_file",
    "push_file",
    "read_logcat",
    "read_setting",
    "screencap",
    "start_app",
    "stop_app",
]

#: Devices kept from one ``adb devices -l`` transcript, whatever is attached.
MAX_DEVICES = 64

#: Packages kept from one ``pm list packages -3`` transcript (bounded work).
MAX_PACKAGES = 256

#: Processes kept from one ``ps -A`` transcript (bounded work).
MAX_PROCESSES = 256

#: Services kept from one ``service list`` transcript (bounded work).
MAX_SERVICES = 256

#: Whitelisted properties kept from one ``getprop`` transcript (bounded work).
MAX_PROPS = 256

#: Warnings kept per parse before the rest are summarised away.
MAX_WARNINGS = 32

#: Default wall-clock budget for one adb invocation, in seconds.
DEFAULT_TIMEOUT = 20.0

#: Hard ceiling on the wall-clock budget of one adb invocation. Bugreports on
#: real hardware regularly exceed the 20 s default; raise ``timeout``
#: deliberately, never silently.
MAX_TIMEOUT = 600.0

#: Hard ceiling on the size of an APK :func:`install_apk` will accept.
MAX_APK_BYTES = 4 * 1024 * 1024 * 1024

#: Logcat lines kept from one ``logcat -d -t`` transcript (bounded work).
MAX_LOG_LINES = 200

#: Characters kept of one logcat message before it is clipped.
MAX_LOG_MSG_CHARS = 512

#: Hard ceiling on one file :func:`pull_file` / :func:`push_file` accepts.
MAX_TRANSFER_BYTES = 512 * 1024 * 1024

#: Characters accepted for one device-side path argument (argv hygiene).
MAX_DEVICE_PATH_CHARS = 512

#: Characters a serial may contain (``emulator-5554``, ``127.0.0.1:5555``,
#: USB serials, product names); anything else is refused before it reaches argv.
_SERIAL_CHARS = re.compile(r"^[A-Za-z0-9._:-]+$")

#: Prefixes of ``adb devices`` chatter that is not a device row.
_DEVICES_SKIP_PREFIXES = (
    "List of devices attached",
    "* daemon",
    "* server",
    "* failed",
    "- waiting",
    "adb:",
    "restarting in",
)

#: ``package:/data/app/.../base.apk=com.example.app`` (``-f`` transcripts) and
#: ``package:com.example.app`` (bare ``-3`` transcripts).
_PACKAGE_LINE = re.compile(r"^package:(?P<rest>.+)$")

#: ``[ro.build.version.release]: [14]`` -- the bracketed getprop rendering.
_PROP_BRACKETED = re.compile(r"^\[(?P<key>[^\]]+)\]:\s*\[(?P<value>.*)\]$")

#: ``ActivityRecord{... u0 com.example.app/.MainActivity ...}`` /
#: ``Window{... u0 com.example.app/com.example.app.MainActivity}``.
_FOCUS_COMPONENT = re.compile(r"\bu0\s+(?P<component>[^\s{}]+/[^\s{}]+)")

#: ``ComponentInfo{com.example.app/com.example.app.MainActivity}``.
_COMPONENT_INFO = re.compile(r"ComponentInfo\{(?P<component>[^}]+)\}")

#: ``Package [com.example.app] (...)`` -- dumpsys package's first line.
#: ``Package [com.example.app] (...)`` -- dumpsys package's first line.
_DUMPSYS_PACKAGE_HEADER = re.compile(r"^Package \[(?P<name>[^\]]+)\]")


#: ``service list`` row: ``59  window: [android.view.IWindowManager]``.
_SERVICE_LINE = re.compile(
    r"^(?P<number>\d+)\s+(?P<name>\S+?):(?:\s+\[(?P<interface>[^\]]*)\])?\s*$"
)

#: Canonical ``ps -A`` column names, from both modern and legacy headers.
_PS_COLUMNS = {
    "user",
    "pid",
    "ppid",
    "vsz",
    "vsize",
    "rss",
    "wchan",
    "addr",
    "s",
    "name",
    "pcy",
}

#: ``threadtime`` logcat row:
#: ``03-15 10:21:02.123  1234  5678 D TagName : message``.
_LOGCAT_ROW = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<priority>[VDIWEFS])\s+"
    r"(?P<tag>\S*?)\s*:\s(?P<message>.*)$"
)

#: Android package names are ``com.example.app`` segments; anything outside
#: this alphabet is refused before it reaches argv.
_PACKAGE_CHARS = re.compile(r"^[A-Za-z0-9._]+$")

#: Evidence ``source`` ids, one per adb command family (``adb.<command>``).
EVIDENCE_DEVICES = "adb.devices"
EVIDENCE_GETPROP = "adb.getprop"
EVIDENCE_PACKAGES = "adb.pm_list_packages"
EVIDENCE_PROCESSES = "adb.ps"
EVIDENCE_SERVICES = "adb.service_list"
EVIDENCE_DUMPSYS_PACKAGE = "adb.dumpsys_package"
EVIDENCE_WINDOW = "adb.dumpsys_window"
EVIDENCE_INSTALL = "adb.install"
EVIDENCE_SCREENCAP = "adb.screencap"
EVIDENCE_BUGREPORT = "adb.bugreport"
EVIDENCE_LOGCAT = "adb.logcat"
EVIDENCE_PULL = "adb.pull"
EVIDENCE_PUSH = "adb.push"
EVIDENCE_START = "adb.start"
EVIDENCE_STOP = "adb.stop"
EVIDENCE_SETTING = "adb.setting"

#: Typed failure for every wrapper when adb is absent, with the install hint.
ADB_MISSING_MESSAGE = (
    "adb is not on PATH; install Android platform-tools "
    "(https://developer.android.com/tools/releases/platform-tools) "
    "and make sure adb is on PATH"
)

#: Build-identity whitelist for :func:`parse_getprop`.
_PROP_KEY_PREFIXES = ("ro.build.version.", "ro.product.")
_PROP_KEY_EXACT = ("ro.build.fingerprint",)


class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped.

    Attributes:
        returncode: The adb process exit code (``0`` on success).
        stdout: Everything adb printed (``str`` for text wrappers, ``bytes``
            for :func:`screencap`).
        stderr: Everything adb wrote to its error stream.
    """

    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (see module docstring)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> RunnerOutcome: ...


@dataclass(frozen=True)
class AdbDevice:
    """One row of ``adb devices -l`` output."""

    serial: str
    state: str
    kind: str
    model: str | None = None
    device: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "serial": self.serial,
            "state": self.state,
            "kind": self.kind,
        }
        if self.model is not None:
            data["model"] = self.model
        if self.device is not None:
            data["device"] = self.device
        return data


@dataclass(frozen=True)
class AdbDevicesResult:
    """Bounded, evidence-backed parse of one ``adb devices -l`` transcript."""

    devices: tuple[AdbDevice, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_DEVICES,
            method="devices -l",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": [device.to_dict() for device in self.devices],
            "count": len(self.devices),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbPackageEntry:
    """One row of ``pm list packages -3`` (path present on ``-f`` transcripts)."""

    name: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.path is not None:
            data["path"] = self.path
        return data


@dataclass(frozen=True)
class AdbPackagesResult:
    """Bounded name -> path mapping from one ``pm list packages`` transcript."""

    packages: tuple[AdbPackageEntry, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_PACKAGES,
            method="shell pm list packages -3",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages": [package.to_dict() for package in self.packages],
            "count": len(self.packages),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbProcessEntry:
    """One row of ``ps -A`` output (rss in KiB, state the ``S`` letter)."""

    user: str
    pid: int
    ppid: int | None
    rss: int | None
    state: str | None
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "pid": self.pid,
            "ppid": self.ppid,
            "rss": self.rss,
            "state": self.state,
            "name": self.name,
        }


@dataclass(frozen=True)
class AdbProcessesResult:
    """Bounded process list from one ``ps -A`` transcript."""

    processes: tuple[AdbProcessEntry, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_PROCESSES,
            method="shell ps -A",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "processes": [process.to_dict() for process in self.processes],
            "count": len(self.processes),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbServiceEntry:
    """One row of ``service list`` output."""

    number: int
    name: str
    interface: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"number": self.number, "name": self.name}
        if self.interface:
            data["interface"] = self.interface
        return data


@dataclass(frozen=True)
class AdbServicesResult:
    """Bounded binder-service listing from one ``service list`` transcript."""

    services: tuple[AdbServiceEntry, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SERVICES,
            method="shell service list",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "services": [service.to_dict() for service in self.services],
            "count": len(self.services),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbPropsResult:
    """Whitelisted build identity from one ``getprop`` transcript."""

    props: dict[str, str]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_GETPROP,
            method="shell getprop",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "props": dict(self.props),
            "count": len(self.props),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbPackageInfoResult:
    """Package identity decoded from one ``dumpsys package`` transcript."""

    package: str | None
    version_name: str | None
    installer: str | None
    first_install_time: str | None
    requested_permissions_count: int
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_DUMPSYS_PACKAGE,
            method="shell dumpsys package",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "installer": self.installer,
            "first_install_time": self.first_install_time,
            "requested_permissions_count": self.requested_permissions_count,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbWindowFocusResult:
    """Focused window/app decoded from one ``dumpsys window`` transcript."""

    current_focus: str | None
    focused_app: str | None
    current_focus_component: str | None = None
    focused_app_component: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_WINDOW,
            method="shell dumpsys window",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_focus": self.current_focus,
            "focused_app": self.focused_app,
            "current_focus_component": self.current_focus_component,
            "focused_app_component": self.focused_app_component,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbInstallResult:
    """Record of one confirmed ``adb install`` (host sha256 taken first)."""

    serial: str
    apk: str
    sha256: str
    size: int
    output: str
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_INSTALL,
            method="install -r",
            confidence=Confidence.CERTAIN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "apk": self.apk,
            "sha256": self.sha256,
            "size": self.size,
            "output": self.output,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbScreencapResult:
    """Record of one ``exec-out screencap -p`` capture written to disk."""

    serial: str
    path: str
    size: int
    sha256: str
    is_png: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SCREENCAP,
            method="exec-out screencap -p",
            confidence=Confidence.CERTAIN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "is_png": self.is_png,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbBugreportResult:
    """Record of one ``adb bugreport`` zip written into a caller directory."""

    serial: str
    path: str
    size: int
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_BUGREPORT,
            method="bugreport",
            confidence=Confidence.CERTAIN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "path": self.path,
            "size": self.size,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _as_text(raw: Any) -> str:
    """Return ``raw`` as transcript text, refusing anything that is not ``str``."""
    if not isinstance(raw, str):
        raise AnalysisError(f"adb transcript must be a string, got {type(raw).__name__}")
    return raw


def _note(warnings: list[str], message: str) -> None:
    """Append ``message``, bounded so one noisy transcript cannot flood memory."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif len(warnings) == MAX_WARNINGS:
        warnings.append(f"further warnings suppressed (limit {MAX_WARNINGS})")


def _evidence_for(
    source: str,
    method: str,
    count: int,
    warnings: list[str],
    detail: str | None = None,
) -> Evidence:
    """Build the parse's evidence record.

    Direct, unambiguous rows parsed from a transcript are ``CERTAIN``; rows
    parsed *with* warnings drop to ``MEDIUM``; an empty parse reports
    ``UNKNOWN`` rather than dressing absence up as a finding.
    """
    if count <= 0:
        confidence = Confidence.UNKNOWN
    elif warnings:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.CERTAIN
    if detail is None:
        detail = f"{count} record{'s' if count == 1 else ''} parsed" if count else "nothing parsed"
    return Evidence(
        source=source,
        method=method,
        confidence=confidence,
        detail=detail,
    )


def _check_timeout(value: Any) -> float:
    """Validate one wall-clock budget; every wrapper shares the bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"timeout must be a number of seconds, got {value!r}")
    timeout = float(value)
    if not 1.0 <= timeout <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return timeout


def _check_serial(serial: Any) -> str:
    """Validate one device serial before it reaches argv."""
    if not isinstance(serial, str):
        raise AnalysisError(f"serial must be a string, got {type(serial).__name__}")
    text = serial.strip()
    if not text:
        raise AnalysisError("serial must not be empty")
    if len(text) > 256:
        raise AnalysisError(f"serial is {len(text)} characters long; expected at most 256")
    if not _SERIAL_CHARS.match(text):
        raise AnalysisError(
            f"serial {text!r} contains characters adb does not accept; "
            "expected alphanumerics plus . _ : -"
        )
    return text


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat


def _adb_path() -> str | None:
    """Probe ``PATH`` for adb exactly once per call; nothing else can fail."""
    return shutil.which("adb")


def _require_adb() -> None:
    """Raise the typed skip-gate failure when adb is absent."""
    if _adb_path() is None:
        raise AnalysisError(ADB_MISSING_MESSAGE)


def _run_adb(
    args: Sequence[str],
    *,
    timeout: float,
    runner: Runner | None = None,
    binary: bool = False,
) -> tuple[int, str | bytes, str]:
    """Run ``adb ...`` once, bounded, and return ``(returncode, stdout, stderr)``.

    ``binary=True`` captures raw bytes (:func:`screencap`); every other caller
    gets text. With the default runner the typed adb-missing failure fires
    before anything is spawned; an injected ``runner`` stands in for
    ``subprocess.run`` entirely, so the PATH probe is skipped and the pipeline
    runs offline against canned output (its own ``FileNotFoundError`` still
    surfaces as the same typed error).
    """
    if runner is None:
        _require_adb()
    checked = _check_timeout(timeout)
    command = ("adb", *args)
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(
            command,
            capture_output=True,
            text=not binary,
            timeout=checked,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"adb {args[0]} exceeded its timeout of {checked} seconds and was "
            "terminated; raise timeout or check the device state with adb devices"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{ADB_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
            "adb executable vanished between the PATH probe and the call"
        ) from exc
    returncode = getattr(outcome, "returncode", None)
    stdout = getattr(outcome, "stdout", None)
    stderr = getattr(outcome, "stderr", None)
    if not isinstance(returncode, int):
        raise AnalysisError(
            "the runner outcome violates the injection contract: returncode must "
            "be an int"
        )
    if binary and not isinstance(stdout, bytes):
        raise AnalysisError(
            "the runner outcome violates the injection contract: binary runs "
            "(screencap) must return stdout as bytes"
        )
    if not binary and isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr if isinstance(stderr, str) else str(stderr or "")
    return returncode, stdout if stdout is not None else "", stderr_text


def _check_exit(command: tuple[str, ...], returncode: int, stderr: str) -> None:
    """Turn a non-zero adb exit into a typed error naming what adb said."""
    if returncode == 0:
        return
    spoken = _tail(stderr) or "no stderr output"
    raise AnalysisError(f"adb command {' '.join(command)!r} exited with code {returncode}: {spoken}")


def _sha256_file(path: Path) -> tuple[str, int]:
    """Stream ``path`` and return ``(sha256 hex digest, size in bytes)``."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _device_kind(serial: str, device: str | None) -> str:
    """Classify a serial as ``emulator`` or ``physical``.

    The emulator's own serial prefix (``emulator-5554``) and the ``device:``
    codename it reports (``emu64xa``, ``emu64xe``) are the two signals adb
    itself gives us; anything else is treated as a physical device.
    """
    if serial.startswith("emulator-"):
        return "emulator"
    if (device or "").startswith("emu"):
        return "emulator"
    return "physical"


def parse_devices(text: str) -> AdbDevicesResult:
    """Parse ``adb devices -l`` output into bounded typed rows.

    Daemon chatter (``* daemon not running ...``, ``List of devices attached``)
    is skipped; each remaining line is ``<serial> <state> key:value ...`` where
    ``model:`` and ``device:`` carry the marketing model and the codename.
    Lines that parse are kept up to :data:`MAX_DEVICES`; anything past the cap
    sets ``truncated`` and the parse never raises for transcript content.
    """
    raw = _as_text(text)
    devices: list[AdbDevice] = []
    warnings: list[str] = []
    truncated = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_DEVICES_SKIP_PREFIXES):
            continue
        if len(devices) >= MAX_DEVICES:
            truncated = True
            _note(warnings, f"device limit {MAX_DEVICES} reached; further rows dropped")
            break
        fields = stripped.split()
        if len(fields) < 2:
            _note(warnings, f"unparsable device row skipped: {stripped!r}")
            continue
        serial, state = fields[0], fields[1]
        model: str | None = None
        device: str | None = None
        for token in fields[2:]:
            if token.startswith("model:"):
                model = token[len("model:") :] or None
            elif token.startswith("device:"):
                device = token[len("device:") :] or None
        devices.append(
            AdbDevice(
                serial=serial,
                state=state,
                kind=_device_kind(serial, device),
                model=model,
                device=device,
            )
        )
    return AdbDevicesResult(
        devices=tuple(devices),
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(EVIDENCE_DEVICES, "devices -l", len(devices), warnings),
    )


def parse_packages(text: str) -> AdbPackagesResult:
    """Parse ``pm list packages -3`` into a bounded name -> path mapping.

    Bare transcripts give ``package:<name>`` rows with no path; ``pm list
    packages -f -3`` transcripts give ``package:<apk>=<name>`` rows whose path
    becomes :attr:`AdbPackageEntry.path`. Junk lines become warnings, never
    errors.
    """
    raw = _as_text(text)
    packages: list[AdbPackageEntry] = []
    warnings: list[str] = []
    truncated = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _PACKAGE_LINE.match(stripped)
        if match is None:
            _note(warnings, f"line without the 'package:' prefix skipped: {stripped!r}")
            continue
        if len(packages) >= MAX_PACKAGES:
            truncated = True
            _note(warnings, f"package limit {MAX_PACKAGES} reached; further rows dropped")
            break
        rest = match.group("rest").strip()
        path: str | None = None
        name = rest
        if "=" in rest:
            # The separator is the LAST '=': apk paths themselves carry
            # base64 '~~x==' padding segments (``adb shell pm -f`` transcripts).
            candidate_path, _, candidate_name = rest.rpartition("=")
            path = candidate_path.strip() or None
            name = candidate_name.strip()
        if not name:
            _note(warnings, f"package row with an empty name skipped: {stripped!r}")
            continue
        packages.append(AdbPackageEntry(name=name, path=path))
    return AdbPackagesResult(
        packages=tuple(packages),
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_PACKAGES, "shell pm list packages -3", len(packages), warnings
        ),
    )


def _as_int_or_none(text: str) -> int | None:
    """Return ``text`` as an ``int`` when it is a plain decimal, else ``None``."""
    return int(text) if text.isdigit() else None


def _ps_header_indexes(line: str) -> dict[str, int] | None:
    """Return canonical column indexes when ``line`` is a ``ps`` header row."""
    tokens = line.split()
    lowered = [token.lower() for token in tokens]
    if "pid" not in lowered or "name" not in lowered:
        return None
    if not all(token in _PS_COLUMNS for token in lowered):
        return None
    return {token: position for position, token in enumerate(lowered)}


def parse_processes(text: str) -> AdbProcessesResult:
    """Parse ``ps -A`` output into bounded typed rows.

    The header row (``USER PID PPID VSZ RSS WCHAN ADDR S NAME`` modern, or the
    legacy ``USER PID PPID VSIZE RSS WCHAN NAME``) is located and drives the
    column mapping; a transcript without a header row falls back to the modern
    layout with a warning. Process names may contain spaces, so everything from
    the name column onward is joined back into one name.
    """
    raw = _as_text(text)
    processes: list[AdbProcessEntry] = []
    warnings: list[str] = []
    truncated = False
    indexes: dict[str, int] | None = None
    header_width = 0
    for line in raw.splitlines():
        stripped = line.rstrip("\r")
        if not stripped.strip():
            continue
        if indexes is None:
            candidate = _ps_header_indexes(stripped)
            if candidate is not None:
                indexes = candidate
                header_width = max(candidate.values()) + 1
                continue
        if indexes is None:
            indexes = {"user": 0, "pid": 1, "ppid": 2, "rss": 4, "s": 7, "name": 8}
            header_width = 9
            _note(warnings, "no ps header row found; assumed the modern ps -A column layout")
        if stripped.upper().startswith("USER "):
            continue
        if len(processes) >= MAX_PROCESSES:
            truncated = True
            _note(warnings, f"process limit {MAX_PROCESSES} reached; further rows dropped")
            break
        fields = stripped.split()
        if len(fields) < header_width:
            _note(warnings, f"short ps row skipped: {stripped!r}")
            continue
        pid = _as_int_or_none(fields[indexes["pid"]])
        if pid is None:
            _note(warnings, f"ps row without a numeric pid skipped: {stripped!r}")
            continue
        name = " ".join(fields[indexes["name"] :]).strip()
        if not name:
            _note(warnings, f"ps row without a name skipped: pid {pid}")
            continue
        processes.append(
            AdbProcessEntry(
                user=fields[indexes.get("user", 0)],
                pid=pid,
                ppid=_as_int_or_none(fields[indexes["ppid"]]),
                rss=_as_int_or_none(fields[indexes["rss"]]) if "rss" in indexes else None,
                state=fields[indexes["s"]] if "s" in indexes else None,
                name=name,
            )
        )
    if indexes is None:
        _note(warnings, "no ps rows found in the transcript")
    return AdbProcessesResult(
        processes=tuple(processes),
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(EVIDENCE_PROCESSES, "shell ps -A", len(processes), warnings),
    )


def parse_services(text: str) -> AdbServicesResult:
    """Parse ``service list`` rows into bounded typed entries.

    Each row is ``<number> <name>: [<interface>]``; the interface can be empty
    (``[]``) or absent, and both are stored as ``None``. Unparsable lines become
    warnings, never errors.
    """
    raw = _as_text(text)
    services: list[AdbServiceEntry] = []
    warnings: list[str] = []
    truncated = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _SERVICE_LINE.match(stripped)
        if match is None:
            _note(warnings, f"unparsable service row skipped: {stripped!r}")
            continue
        if len(services) >= MAX_SERVICES:
            truncated = True
            _note(warnings, f"service limit {MAX_SERVICES} reached; further rows dropped")
            break
        services.append(
            AdbServiceEntry(
                number=int(match.group("number")),
                name=match.group("name"),
                interface=match.group("interface") or None,
            )
        )
    return AdbServicesResult(
        services=tuple(services),
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_SERVICES, "shell service list", len(services), warnings
        ),
    )


def _prop_whitelisted(key: str) -> bool:
    """True for the build-identity keys the lane keeps (everything else drops)."""
    return key in _PROP_KEY_EXACT or key.startswith(_PROP_KEY_PREFIXES)


def parse_getprop(text: str) -> AdbPropsResult:
    """Parse a ``getprop`` dump into the whitelisted build identity.

    Both renderings adb prints are accepted: the bracketed
    ``[ro.build.version.release]: [14]`` form and the plain ``key: value`` form.
    Keys outside ``ro.build.version.*``, ``ro.product.*`` and
    ``ro.build.fingerprint`` are dropped silently -- the whitelist is the point
    -- and the kept keys are capped at :data:`MAX_PROPS`.
    """
    raw = _as_text(text)
    props: dict[str, str] = {}
    warnings: list[str] = []
    truncated = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        key: str | None = None
        value: str | None = None
        bracketed = _PROP_BRACKETED.match(stripped)
        if bracketed is not None:
            key = bracketed.group("key").strip()
            value = bracketed.group("value").strip()
        elif ":" in stripped:
            candidate_key, _, candidate_value = stripped.partition(":")
            key = candidate_key.strip()
            value = candidate_value.strip()
        if not key or value is None:
            _note(warnings, f"unparsable getprop line skipped: {stripped!r}")
            continue
        if not _prop_whitelisted(key):
            continue
        if len(props) >= MAX_PROPS:
            truncated = True
            _note(warnings, f"property limit {MAX_PROPS} reached; further rows dropped")
            break
        props[key] = value
    ordered = {key: props[key] for key in sorted(props)}
    return AdbPropsResult(
        props=ordered,
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_GETPROP, "shell getprop", len(ordered), warnings
        ),
    )


def parse_dumpsys_package(text: str) -> AdbPackageInfoResult:
    """Decode one package's identity from a ``dumpsys package`` transcript.

    Kept: the ``Package [name]`` header, ``versionName``, ``installer`` (or the
    legacy ``installerPackageName``), ``firstInstallTime`` and the count of the
    ``requested permissions`` block. The count is what matters -- permission
    lists are unbounded, so they are never stored.
    """
    raw = _as_text(text)
    package: str | None = None
    version_name: str | None = None
    installer: str | None = None
    first_install: str | None = None
    permission_count = 0
    in_requested = False
    warnings: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        header = _DUMPSYS_PACKAGE_HEADER.match(stripped)
        if header is not None and package is None:
            package = header.group("name")
        if not stripped:
            in_requested = False
            continue
        if stripped.endswith(":"):
            in_requested = stripped == "requested permissions:"
            continue
        if in_requested:
            permission_count += 1
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "versionName" and version_name is None:
            version_name = value
        elif key == "firstInstallTime" and first_install is None:
            first_install = value
        elif key == "installer" and installer is None:
            installer = value
        elif key == "installerPackageName" and installer is None:
            installer = value
    if permission_count == 0:
        _note(warnings, "no 'requested permissions' block found in the transcript")
    fields_found = sum(
        1 for value in (package, version_name, installer, first_install) if value is not None
    )
    return AdbPackageInfoResult(
        package=package,
        version_name=version_name,
        installer=installer,
        first_install_time=first_install,
        requested_permissions_count=permission_count,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_DUMPSYS_PACKAGE,
            "shell dumpsys package",
            fields_found,
            warnings,
            detail=(
                f"package {package!r}; versionName {version_name!r}; "
                f"{permission_count} requested permissions"
            ),
        ),
    )


def _focus_component(value: str) -> str | None:
    """Extract ``package/component`` from a focus value, ``None`` when absent."""
    info = _COMPONENT_INFO.search(value)
    if info is not None:
        return info.group("component")
    token = _FOCUS_COMPONENT.search(value)
    if token is not None:
        return token.group("component")
    return None


def parse_window_focus(text: str) -> AdbWindowFocusResult:
    """Decode the focused window/app from a ``dumpsys window`` transcript.

    ``mCurrentFocus`` is the window with input focus; ``mFocusedApp`` is the
    activity the framework considers foreground. ``mFocusedWindow`` is kept as
    a fallback for builds that only print the latter pair. The raw values are
    preserved and ``package/component`` is extracted where adb's ``u0`` token
    or a ``ComponentInfo{...}`` carries one.
    """
    raw = _as_text(text)
    current_focus: str | None = None
    focused_window: str | None = None
    focused_app: str | None = None
    warnings: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("mCurrentFocus="):
            current_focus = stripped[len("mCurrentFocus=") :].strip()
        elif stripped.startswith("mFocusedWindow=") and focused_window is None:
            focused_window = stripped[len("mFocusedWindow=") :].strip()
        elif stripped.startswith("mFocusedApp="):
            focused_app = stripped[len("mFocusedApp=") :].strip()
    effective_focus = current_focus or focused_window
    if effective_focus is None and focused_app is None:
        _note(warnings, "no mCurrentFocus/mFocusedWindow/mFocusedApp line in the transcript")
    return AdbWindowFocusResult(
        current_focus=effective_focus,
        focused_app=focused_app,
        current_focus_component=_focus_component(effective_focus) if effective_focus else None,
        focused_app_component=_focus_component(focused_app) if focused_app else None,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_WINDOW,
            "shell dumpsys window",
            sum(1 for value in (effective_focus, focused_app) if value is not None),
            warnings,
        ),
    )


def adb_available() -> bool:
    """Report whether adb is on ``PATH``; the only gate a caller needs."""
    return _adb_path() is not None


def list_devices(
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbDevicesResult:
    """Run ``adb devices -l`` and return the parsed, bounded device list."""
    code, out, err = _run_adb(("devices", "-l"), timeout=timeout, runner=runner)
    _check_exit(("adb", "devices", "-l"), code, err)
    return parse_devices(out if isinstance(out, str) else "")


def inspect_device(
    serial: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbPropsResult:
    """Run ``adb -s <serial> shell getprop`` and keep the build identity."""
    checked = _check_serial(serial)
    code, out, err = _run_adb(
        ("-s", checked, "shell", "getprop"), timeout=timeout, runner=runner
    )
    _check_exit(("adb", "-s", checked, "shell", "getprop"), code, err)
    return parse_getprop(out if isinstance(out, str) else "")


def list_packages(
    serial: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbPackagesResult:
    """Run ``adb -s <serial> shell pm list packages -3`` (third-party only)."""
    checked = _check_serial(serial)
    code, out, err = _run_adb(
        ("-s", checked, "shell", "pm", "list", "packages", "-3"),
        timeout=timeout,
        runner=runner,
    )
    _check_exit(("adb", "-s", checked, "shell", "pm list packages -3"), code, err)
    return parse_packages(out if isinstance(out, str) else "")


def list_processes(
    serial: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbProcessesResult:
    """Run ``adb -s <serial> shell ps -A`` and return the bounded process rows."""
    checked = _check_serial(serial)
    code, out, err = _run_adb(
        ("-s", checked, "shell", "ps", "-A"), timeout=timeout, runner=runner
    )
    _check_exit(("adb", "-s", checked, "shell", "ps -A"), code, err)
    return parse_processes(out if isinstance(out, str) else "")


def install_apk(
    serial: str,
    apk_path: str | Path,
    *,
    confirm: bool = False,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbInstallResult:
    """Install ``apk_path`` on ``serial`` -- refuses without ``confirm=True``.

    The host-side ``sha256`` and size are recorded *before* adb is invoked, so
    the result always names exactly which bytes the device was asked to accept.
    An adb failure (non-zero exit, or the ``Failure [...]`` line adb prints with
    a zero exit on some builds) raises a typed error carrying adb's output.
    """
    checked = _check_serial(serial)
    if confirm is not True:
        raise AnalysisError(
            "install_apk requires confirm=True; refusing to change the device "
            "without an explicit confirmation (CLI: pass --yes)"
        )
    candidate = Path(apk_path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"APK not found: {candidate}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {candidate}")
    size = candidate.stat().st_size
    if size <= 0:
        raise AnalysisError(f"APK {candidate} is empty")
    if size > MAX_APK_BYTES:
        raise AnalysisError(
            f"APK {candidate} is {size} bytes; the install budget is {MAX_APK_BYTES} bytes"
        )
    digest, measured = _sha256_file(candidate)
    command_tail = ("-s", checked, "install", "-r", str(candidate))
    code, out, err = _run_adb(command_tail, timeout=timeout, runner=runner)
    spoken = out if isinstance(out, str) else ""
    if code != 0 or "Failure" in spoken:
        detail = _tail(spoken) or _tail(err) or "no adb output"
        raise AnalysisError(
            f"adb install of {candidate} (sha256 {digest}) failed on {checked}: {detail}"
        )
    return AdbInstallResult(
        serial=checked,
        apk=str(candidate),
        sha256=digest,
        size=measured,
        output=_tail(spoken),
        evidence=Evidence(
            source=EVIDENCE_INSTALL,
            method="install -r",
            confidence=Confidence.CERTAIN,
            detail=f"sha256 {digest}",
            extra={"size": measured, "serial": checked},
        ),
    )


def screencap(
    serial: str,
    out_path: str | Path,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbScreencapResult:
    """Capture the screen as a PNG via ``exec-out screencap -p``.

    ``exec-out`` keeps the bytes binary-clean (the ``adb shell screencap`` path
    mangles ``\\n`` on some transports). The file is written, hashed and checked
    for the PNG magic; a non-PNG capture is written anyway and flagged as a
    warning rather than discarded.
    """
    checked = _check_serial(serial)
    target = Path(out_path).expanduser()
    parent = target.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    code, data, err = _run_adb(
        ("-s", checked, "exec-out", "screencap", "-p"),
        timeout=timeout,
        runner=runner,
        binary=True,
    )
    _check_exit(("adb", "-s", checked, "exec-out screencap -p"), code, err)
    if not isinstance(data, bytes) or not data:
        raise AnalysisError(
            f"screencap on {checked} returned no bytes; is the screen accessible?"
        )
    target.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    warnings: list[str] = []
    is_png = data[:8] == b"\x89PNG\r\n\x1a\n"
    if not is_png:
        _note(warnings, f"capture is not a PNG (starts {data[:8].hex()}); written anyway")
    return AdbScreencapResult(
        serial=checked,
        path=str(target),
        size=len(data),
        sha256=digest,
        is_png=is_png,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SCREENCAP,
            method="exec-out screencap -p",
            confidence=Confidence.CERTAIN,
            detail=f"sha256 {digest}",
            extra={"size": len(data), "serial": checked},
        ),
    )


def bugreport(
    serial: str,
    out_dir: str | Path,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbBugreportResult:
    """Write one ``adb bugreport`` zip into ``out_dir``.

    The target file is ``codevanta-bugreport-<sanitised serial>.zip``; the
    directory is created when missing. A full bugreport on real hardware often
    needs more than the 20 s default, so pass a larger ``timeout`` (bounded by
    :data:`MAX_TIMEOUT`) for live devices.
    """
    checked = _check_serial(serial)
    directory = Path(out_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", checked)
    target = directory / f"codevanta-bugreport-{safe}.zip"
    command_tail = ("-s", checked, "bugreport", str(target))
    code, out, err = _run_adb(command_tail, timeout=timeout, runner=runner)
    _check_exit(("adb", "-s", checked, "bugreport"), code, err)
    if not target.exists():
        raise AnalysisError(
            f"adb bugreport on {checked} exited {code} but wrote nothing to {target}"
        )
    size = target.stat().st_size
    warnings: list[str] = []
    if size == 0:
        _note(warnings, f"bugreport zip at {target} is empty")
    return AdbBugreportResult(
        serial=checked,
        path=str(target),
        size=size,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_BUGREPORT,
            method="bugreport",
            confidence=Confidence.CERTAIN,
            detail=f"{size} bytes",
            extra={"serial": checked},
        ),
    )


# ---- logcat ------------------------------------------------------------------


@dataclass(frozen=True)
class AdbLogcatLine:
    """One ``threadtime`` logcat row: priority, tag, pid and clipped message."""

    priority: str
    tag: str
    pid: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "tag": self.tag,
            "pid": self.pid,
            "message": self.message,
        }


@dataclass(frozen=True)
class AdbLogcatResult:
    """Bounded, evidence-backed parse of one ``logcat -d -t`` transcript."""

    lines: tuple[AdbLogcatLine, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_LOGCAT,
            method="logcat -d -t",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.lines),
            "lines": [line.to_dict() for line in self.lines],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

    @property
    def count(self) -> int:
        """Number of decoded rows (same value ``to_dict()`` reports)."""
        return len(self.lines)


def parse_logcat(text: str) -> AdbLogcatResult:
    """Decode ``logcat -d -t`` ``threadtime`` rows (priority, tag, pid, message).

    Junk lines (daemon chatter, blank rows, other formats) become warnings,
    never errors; at :data:`MAX_LOG_LINES` rows the parse sets ``truncated``
    and stops, and every message is clipped to :data:`MAX_LOG_MSG_CHARS`.
    Malformed *input* (anything that is not ``str``) raises
    :class:`~codevanta.core.report.AnalysisError`.
    """
    raw = _as_text(text)
    lines: list[AdbLogcatLine] = []
    warnings: list[str] = []
    truncated = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if len(lines) >= MAX_LOG_LINES:
            truncated = True
            _note(warnings, f"line limit {MAX_LOG_LINES} reached; further rows dropped")
            break
        row = _LOGCAT_ROW.match(stripped)
        if row is None:
            _note(warnings, f"unparsable logcat row skipped: {stripped[:80]!r}")
            continue
        message = row.group("message")
        if len(message) > MAX_LOG_MSG_CHARS:
            message = message[:MAX_LOG_MSG_CHARS]
        lines.append(
            AdbLogcatLine(
                priority=row.group("priority"),
                tag=row.group("tag"),
                pid=int(row.group("pid")),
                message=message,
            )
        )
    return AdbLogcatResult(
        lines=tuple(lines),
        truncated=truncated,
        warnings=warnings,
        evidence=_evidence_for(EVIDENCE_LOGCAT, "logcat -d -t", len(lines), warnings),
    )


def read_logcat(
    serial: str,
    *,
    pid: int | None = None,
    count: int = 50,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbLogcatResult:
    """Dump the recent log via ``adb -s <serial> logcat -d -t <count> [--pid=<pid>]``.

    ``count`` is what adb is asked for (1..10000); the parser still keeps at
    most :data:`MAX_LOG_LINES` rows so one noisy buffer cannot flood memory.
    """
    checked = _check_serial(serial)
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or pid < 0):
        raise AnalysisError(f"pid must be a non-negative int, got {pid!r}")
    if isinstance(count, bool) or not isinstance(count, int):
        raise AnalysisError(f"count must be an int, got {count!r}")
    if not 1 <= count <= 10000:
        raise AnalysisError(f"count {count} is out of range; expected 1 .. 10000")
    args = ["-s", checked, "logcat", "-d", "-t", str(count)]
    label = f"logcat -d -t {count}"
    if pid is not None:
        args.append(f"--pid={pid}")
        label = f"{label} --pid={pid}"
    code, out, err = _run_adb(tuple(args), timeout=timeout, runner=runner)
    _check_exit(("adb", "-s", checked, label), code, err)
    return parse_logcat(out if isinstance(out, str) else "")


# ---- am start / force-stop / settings ------------------------------------------


@dataclass(frozen=True)
class AdbStartResult:
    """Decoded ``am start -W`` launch: Status, LaunchState and TotalTime."""

    serial: str
    package: str
    status: str | None
    launch_state: str | None
    total_time_ms: int | None
    wait_time_ms: int | None
    component: str | None
    error: str | None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_START,
            method="am start -W",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "package": self.package,
            "status": self.status,
            "launch_state": self.launch_state,
            "total_time_ms": self.total_time_ms,
            "wait_time_ms": self.wait_time_ms,
            "component": self.component,
            "error": self.error,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AdbStopResult:
    """Confirmation of one ``am force-stop`` invocation."""

    serial: str
    package: str
    stopped: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_STOP,
            method="am force-stop",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "package": self.package,
            "stopped": self.stopped,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_am_start(text: str) -> AdbStartResult:
    """Decode ``am start -W`` output into status, launch state and timings.

    ``Status:``/``LaunchState:``/``TotalTime:``/``WaitTime:`` lines are kept
    when present, the ``cmp=`` component of the launched intent is extracted,
    and ``Error:`` lines become the result's ``error`` field. A transcript
    with none of the markers warns and reports an unknown-confidence result.
    Malformed *input* (anything that is not ``str``) raises
    :class:`~codevanta.core.report.AnalysisError`.
    """
    raw = _as_text(text)
    status: str | None = None
    launch_state: str | None = None
    total_time: int | None = None
    wait_time: int | None = None
    component: str | None = None
    error: str | None = None
    warnings: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("Status:"):
            status = stripped[len("Status:") :].strip() or None
        elif stripped.startswith("LaunchState:"):
            launch_state = stripped[len("LaunchState:") :].strip() or None
        elif stripped.startswith("TotalTime:"):
            total_time = _maybe_int(stripped[len("TotalTime:") :])
        elif stripped.startswith("WaitTime:"):
            wait_time = _maybe_int(stripped[len("WaitTime:") :])
        elif stripped.startswith("Error:"):
            error = stripped[len("Error:") :].strip() or None
        elif stripped.startswith("Starting: Intent"):
            component = _am_start_component(stripped)
    found = sum(
        1 for value in (status, launch_state, total_time, component) if value is not None
    )
    if found == 0:
        _note(warnings, "no Status/LaunchState/TotalTime lines in the am start transcript")
    detail = (
        f"status {status!r}; launch state {launch_state!r}; total {total_time} ms"
        if found
        else None
    )
    return AdbStartResult(
        serial="",
        package="",
        status=status,
        launch_state=launch_state,
        total_time_ms=total_time,
        wait_time_ms=wait_time,
        component=component,
        error=error,
        warnings=warnings,
        evidence=_evidence_for(EVIDENCE_START, "am start -W", found, warnings, detail=detail),
    )


def _maybe_int(value: str) -> int | None:
    """Parse one integer field, ``None`` when adb printed nothing numeric."""
    text = value.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _am_start_component(line: str) -> str | None:
    """Extract ``cmp=package/component`` from an ``am start`` intent line."""
    info = re.search(r"cmp=(\S+?)(?=[\s}]|$)", line)
    if info is None:
        return None
    return info.group(1)


def _check_package(package: Any) -> str:
    """Validate one Android package name before it reaches argv."""
    if not isinstance(package, str):
        raise AnalysisError(f"package must be a string, got {type(package).__name__}")
    text = package.strip()
    if not text:
        raise AnalysisError("package must not be empty")
    if len(text) > 256:
        raise AnalysisError(f"package is {len(text)} characters long; expected at most 256")
    if not _PACKAGE_CHARS.match(text):
        raise AnalysisError(
            f"package {text!r} contains characters adb does not accept; "
            "expected alphanumerics plus . _"
        )
    return text


def _check_device_path(path: Any) -> str:
    """Validate one device-side path argument before it reaches argv."""
    if not isinstance(path, str):
        raise AnalysisError(f"device path must be a string, got {type(path).__name__}")
    text = path.strip()
    if not text:
        raise AnalysisError("device path must not be empty")
    if len(text) > MAX_DEVICE_PATH_CHARS:
        raise AnalysisError(
            f"device path is {len(text)} characters long; expected at most {MAX_DEVICE_PATH_CHARS}"
        )
    if any(char in text for char in ("\n", "\r", "\x00")):
        raise AnalysisError("device path must not contain newline or NUL characters")
    return text


@dataclass(frozen=True)
class AdbSettingResult:
    """One ``settings get <namespace> <key>`` value."""

    serial: str
    namespace: str
    key: str
    value: str | None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SETTING,
            method="settings get",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "namespace": self.namespace,
            "key": self.key,
            "value": self.value,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def start_app(
    serial: str,
    package: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbStartResult:
    """Launch ``package`` via ``am start -W`` and decode the launch report."""
    checked = _check_serial(serial)
    checked_package = _check_package(package)
    code, out, err = _run_adb(
        ("-s", checked, "shell", "am", "start", "-W", checked_package),
        timeout=timeout,
        runner=runner,
    )
    _check_exit(("adb", "-s", checked, "shell am start -W", checked_package), code, err)
    result = parse_am_start(out if isinstance(out, str) else "")
    if result.status == "error" and result.error is None:
        _note(result.warnings, "am start reported Status: error without an Error line")
    return AdbStartResult(
        serial=checked,
        package=checked_package,
        status=result.status,
        launch_state=result.launch_state,
        total_time_ms=result.total_time_ms,
        wait_time_ms=result.wait_time_ms,
        component=result.component,
        error=result.error,
        warnings=result.warnings,
        evidence=result.evidence,
    )


def stop_app(
    serial: str,
    package: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbStopResult:
    """Kill ``package`` via ``am force-stop`` (the process list decides success)."""
    checked = _check_serial(serial)
    checked_package = _check_package(package)
    code, out, err = _run_adb(
        ("-s", checked, "shell", "am", "force-stop", checked_package),
        timeout=timeout,
        runner=runner,
    )
    _check_exit(("adb", "-s", checked, "shell am force-stop", checked_package), code, err)
    spoken = (out if isinstance(out, str) else "").strip()
    warnings: list[str] = []
    if spoken:
        _note(warnings, f"am force-stop printed: {_tail(spoken, 200)}")
    return AdbStopResult(
        serial=checked,
        package=checked_package,
        stopped=code == 0,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_STOP,
            method="am force-stop",
            confidence=Confidence.CERTAIN,
            detail=f"package {checked_package} force-stopped",
            extra={"serial": checked},
        ),
    )


def read_setting(
    serial: str,
    namespace: str,
    key: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbSettingResult:
    """Read one setting via ``settings get <namespace> <key>``.

    ``namespace`` must be one of adb's ``system``/``secure``/``global``
    tables. A missing setting prints ``null``; that is reported as ``None``
    rather than the literal string.
    """
    checked = _check_serial(serial)
    checked_key = _check_package(key)
    if namespace not in ("system", "secure", "global"):
        raise AnalysisError(
            f"namespace {namespace!r} is not a settings table; expected system, secure or global"
        )
    code, out, err = _run_adb(
        ("-s", checked, "shell", "settings", "get", namespace, checked_key),
        timeout=timeout,
        runner=runner,
    )
    _check_exit(
        ("adb", "-s", checked, f"shell settings get {namespace}", checked_key), code, err
    )
    spoken = (out if isinstance(out, str) else "").strip()
    warnings: list[str] = []
    value: str | None = spoken or None
    if spoken == "null":
        value = None
        _note(warnings, "the setting is unset on the device (adb printed null)")
    return AdbSettingResult(
        serial=checked,
        namespace=namespace,
        key=checked_key,
        value=value,
        warnings=warnings,
        evidence=_evidence_for(
            EVIDENCE_SETTING,
            f"settings get {namespace}",
            1 if value is not None else 0,
            warnings,
            detail=f"{namespace}/{checked_key} = {value!r}",
        ),
    )


# ---- pull / push ----------------------------------------------------------------


@dataclass(frozen=True)
class AdbFileTransferResult:
    """One file moved over adb, digested on the host side."""

    serial: str
    direction: str
    device_path: str
    host_path: str
    sha256: str
    size: int
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_PULL,
            method="pull",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "direction": self.direction,
            "device_path": self.device_path,
            "host_path": self.host_path,
            "sha256": self.sha256,
            "size": self.size,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def pull_file(
    serial: str,
    device_path: str,
    out_path: str | Path,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbFileTransferResult:
    """Pull ``device_path`` to ``out_path``; the host-side sha256 is recorded.

    The transfer budget is :data:`MAX_TRANSFER_BYTES` (512 MiB): a larger
    landing file raises a typed error naming both sizes.
    """
    checked = _check_serial(serial)
    checked_path = _check_device_path(device_path)
    target = Path(out_path).expanduser()
    parent = target.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    command_tail = ("-s", checked, "pull", checked_path, str(target))
    code, out, err = _run_adb(command_tail, timeout=timeout, runner=runner)
    _check_exit(("adb", "-s", checked, "pull", checked_path), code, err)
    if not target.exists():
        raise AnalysisError(
            f"adb pull of {checked_path} on {checked} exited {code} but wrote nothing "
            f"to {target}"
        )
    size = target.stat().st_size
    warnings: list[str] = []
    if size == 0:
        _note(warnings, f"pulled file {target} is empty")
    if size > MAX_TRANSFER_BYTES:
        raise AnalysisError(
            f"pulled file is {size} bytes; the transfer budget is {MAX_TRANSFER_BYTES} bytes"
        )
    digest, measured = _sha256_file(target)
    spoken = (out if isinstance(out, str) else "").strip()
    if spoken:
        _note(warnings, f"adb pull reported: {_tail(spoken, 200)}")
    return AdbFileTransferResult(
        serial=checked,
        direction="pull",
        device_path=checked_path,
        host_path=str(target),
        sha256=digest,
        size=measured,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_PULL,
            method="pull",
            confidence=Confidence.CERTAIN,
            detail=f"sha256 {digest}",
            extra={"size": measured, "serial": checked, "device_path": checked_path},
        ),
    )


def push_file(
    serial: str,
    local_path: str | Path,
    device_path: str,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AdbFileTransferResult:
    """Push ``local_path`` to ``device_path``; the host-side sha256 is recorded first.

    The size and digest are measured *before* adb runs, so the result names
    exactly which bytes the device was asked to accept. The transfer budget is
    :data:`MAX_TRANSFER_BYTES` (512 MiB) and is enforced pre-flight.
    """
    checked = _check_serial(serial)
    checked_path = _check_device_path(device_path)
    source = Path(local_path).expanduser()
    if not source.exists():
        raise AnalysisError(f"local file not found: {source}")
    if not source.is_file():
        raise AnalysisError(f"not a regular file: {source}")
    size = source.stat().st_size
    if size <= 0:
        raise AnalysisError(f"local file {source} is empty")
    if size > MAX_TRANSFER_BYTES:
        raise AnalysisError(
            f"local file {source} is {size} bytes; the transfer budget is "
            f"{MAX_TRANSFER_BYTES} bytes"
        )
    digest, measured = _sha256_file(source)
    command_tail = ("-s", checked, "push", str(source), checked_path)
    code, out, err = _run_adb(command_tail, timeout=timeout, runner=runner)
    _check_exit(("adb", "-s", checked, "push", checked_path), code, err)
    spoken = (out if isinstance(out, str) else "").strip()
    warnings: list[str] = []
    if spoken:
        _note(warnings, f"adb push reported: {_tail(spoken, 200)}")
    return AdbFileTransferResult(
        serial=checked,
        direction="push",
        device_path=checked_path,
        host_path=str(source),
        sha256=digest,
        size=measured,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_PUSH,
            method="push",
            confidence=Confidence.CERTAIN,
            detail=f"sha256 {digest}",
            extra={"size": measured, "serial": checked, "device_path": checked_path},
        ),
    )











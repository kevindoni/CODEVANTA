"""Network capture around a target command: tshark records while the target runs.

The net lane closes the verification gap the proc lane leaves open: download
managers, updaters and C2-style stubs talk to the network, so a faithful
recreation must be checked against *what actually went over the wire*, not just
what the process printed. :func:`capture_around` composes two existing honest
primitives:

* the owned-subprocess contract of
  :func:`codevanta.analysis.proc_capture.capture_process` (argv form, pipes,
  bounded output and wall clock) runs the *caller-selected command*; and
* a background ``tshark`` process -- ``tshark -i <iface> -a duration:<n> -w
  <pcap> -q`` -- records the packets around it and auto-stops after the
  duration, so there is no unbounded capture even if the target hangs.

Honesty rules:

* live capture is **privileged**: on Windows it additionally needs
  administrator rights and Npcap/WinPcap installed; without them ``tshark``
  starts but records nothing (or ``-D`` lists nothing). Every MCP tool built on
  this module says so, and the availability gate returns an *honest unavailable
  result* instead of pretending to have captured traffic;
* everything is **bounded**: at most :data:`MAX_CAPTURE_SECONDS` (60) seconds of
  capture, at most :data:`MAX_ARGS` (32) argv items for the target, the join on
  the background tshark gets at most :data:`TSHARK_JOIN_GRACE_SECONDS` beyond
  the auto-stop duration before it is killed, and interface listings are capped
  at :data:`MAX_INTERFACES` (32) entries;
* every stage is named: startup, join and summary failures surface as typed
  errors or warnings that say *which* stage failed (``tshark-start``,
  ``tshark-join``, ``pcap-missing``, ``summary``), never a bare traceback.

Injectable seams: ``capture_runner`` stands in for ``subprocess.Popen`` (the
background tshark; it must return a ``wait``/``kill``/``returncode``-shaped
handle), ``proc_runner`` for the target's ``subprocess.run`` (the
:mod:`codevanta.analysis.proc_capture` contract) and ``summary_runner`` for the
offline ``tshark -r`` read of the finished pcap (the
:mod:`codevanta.analysis.tshark_bridge` contract). The offline tests drive all
three with fakes and never spawn a real tshark.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.analysis.proc_capture import ProcCapture, ProcRunner, capture_process
from codevanta.analysis.tshark_bridge import (
    DEFAULT_PACKET_LIMIT,
    TSHARK_MISSING_MESSAGE,
    Runner,
    pcap_fields,
    tshark_available,
)
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "CaptureProcess",
    "CaptureStarter",
    "DEFAULT_CAPTURE_SECONDS",
    "EVIDENCE_METHOD",
    "EVIDENCE_SOURCE",
    "LIVE_CAPTURE_NOTE",
    "MAX_ARGS",
    "MAX_CAPTURE_SECONDS",
    "MAX_INTERFACES",
    "MIN_CAPTURE_SECONDS",
    "NET_UNAVAILABLE_MESSAGE",
    "SUMMARY_FIELDS",
    "TSHARK_JOIN_GRACE_SECONDS",
    "TSHARK_LIST_TIMEOUT",
    "NetCaptureResult",
    "capture_around",
    "list_interfaces",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "net.capture"

#: Evidence ``method`` for a capture composed around a target run.
EVIDENCE_METHOD = "tshark-around-run"

#: Numbered ``tshark -D`` lines are capped; the rest is summarised away.
MAX_INTERFACES = 32

#: Lowest and highest capture window accepted, in seconds.
MIN_CAPTURE_SECONDS = 1
MAX_CAPTURE_SECONDS = 60

#: Default capture window (seconds) offered by the MCP layer.
DEFAULT_CAPTURE_SECONDS = 10

#: Hard ceiling on the target's argv arguments (same bound as the proc lane).
MAX_ARGS = 32

#: Wall-clock budget for one ``tshark -D`` interface listing, in seconds.
TSHARK_LIST_TIMEOUT = 15.0

#: Extra seconds the background tshark gets past its auto-stop duration before
#: the bounded join kills it. tshark flushes and closes the pcap on its own
#: ``-a duration`` stop; the grace only covers process teardown.
TSHARK_JOIN_GRACE_SECONDS = 15.0

#: First fields requested from the finished pcap for the offline summary.
SUMMARY_FIELDS = ("frame.number", "frame.len", "ip.src", "ip.dst")

#: Shown whenever tshark is missing: the environment, not the caller, is at
#: fault, and the privileged bits live capture needs on Windows are named.
LIVE_CAPTURE_NOTE = (
    "live packet capture additionally requires administrator privileges and "
    "Npcap/WinPcap on Windows; without them tshark starts but records no packets"
)

#: The honest unavailable message for both tools when tshark is absent.
NET_UNAVAILABLE_MESSAGE = (
    f"{TSHARK_MISSING_MESSAGE}. {LIVE_CAPTURE_NOTE}"
)

#: One ``tshark -D`` line: ``1. \\Device\\NPF_{GUID} (Adapter name)``.
_INTERFACE_LINE_RE = re.compile(r"^\s*(\d{1,3})\.\s+(.+?)\s*$")

#: Trailing ``(description)`` on a ``tshark -D`` device, when present.
_INTERFACE_DESC_RE = re.compile(r"^(.*?)\s+\((.*)\)$")

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

_PCAP_COUNTER_LOCK = threading.Lock()
_PCAP_COUNTER = 0

class CaptureProcess(Protocol):
    """Popen-shaped handle for the background tshark process."""

    returncode: int | None

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int | None: ...

    def kill(self) -> None: ...


class CaptureStarter(Protocol):
    """The injectable stand-in for ``subprocess.Popen`` (offline tests)."""

    def __call__(self, command: list[str], **kwargs: Any) -> CaptureProcess: ...


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _check_capture_seconds(value: Any) -> int:
    """Validate the capture window against 1 .. :data:`MAX_CAPTURE_SECONDS`."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(
            f"capture_seconds must be an integer number of seconds, got {value!r}"
        )
    if not MIN_CAPTURE_SECONDS <= value <= MAX_CAPTURE_SECONDS:
        raise AnalysisError(
            f"capture_seconds {value} is out of range; expected "
            f"{MIN_CAPTURE_SECONDS} .. {MAX_CAPTURE_SECONDS} seconds"
        )
    return int(value)


def _check_interface(value: Any) -> str:
    """Validate the capture interface: the literal ``tshark -i`` argument."""
    if not isinstance(value, str) or not value.strip():
        raise AnalysisError(f"interface must be a non-empty string, got {value!r}")
    return value.strip()


def _check_output_directory(value: Any) -> Path:
    """Validate the output directory and create it when missing."""
    if isinstance(value, bool) or not isinstance(value, (str, Path)):
        raise AnalysisError(
            f"output_directory must be a directory path, got {type(value).__name__}"
        )
    text = str(value).strip()
    if not text:
        raise AnalysisError("output_directory must be a non-empty directory path")
    directory = Path(text)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AnalysisError(f"output_directory is not usable: {exc}") from exc
    return directory


def _check_arguments(arguments: Any) -> tuple[str, ...]:
    """Pre-check the target's argument count; typing is the proc lane's job."""
    if arguments is None:
        return ()
    if isinstance(arguments, (str, bytes)) or not isinstance(arguments, Sequence):
        raise AnalysisError(
            f"arguments must be a list of strings, got {type(arguments).__name__}"
        )
    if len(arguments) > MAX_ARGS:
        raise AnalysisError(
            f"too many arguments: {len(arguments)} given, at most {MAX_ARGS} accepted"
        )
    return tuple(str(item) for item in arguments)

def _next_pcap_number() -> int:
    """Hand out the next monotonic pcap sequence number (per server process)."""
    global _PCAP_COUNTER
    with _PCAP_COUNTER_LOCK:
        _PCAP_COUNTER += 1
        return _PCAP_COUNTER


def _digest_file(path: Path) -> tuple[int, str]:
    """Stream-sha256 one file; returns ``(size_bytes, hex_digest)``."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _text_outcome(outcome: Any) -> tuple[int | None, str, str]:
    """Normalise one run-shaped runner outcome to ``(code, stdout, stderr)``."""
    code = getattr(outcome, "returncode", None)
    stdout = getattr(outcome, "stdout", None)
    stderr = getattr(outcome, "stderr", None)
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return (
        code if isinstance(code, int) else None,
        stdout if isinstance(stdout, str) else "",
        stderr if isinstance(stderr, str) else "",
    )


def _unavailable(message: str, warnings: list[str] | None = None) -> dict[str, Any]:
    """The honest shape both tools return when tshark cannot be used."""
    return {
        "available": False,
        "count": 0,
        "interfaces": [],
        "truncated": False,
        "message": message,
        "warnings": list(warnings or []),
        "evidence": Evidence(
            source=EVIDENCE_SOURCE,
            method="availability-probe",
            confidence=Confidence.LOW,
            detail="tshark is not usable on this machine; nothing was captured",
        ).to_dict(),
    }

def list_interfaces(capture_runner: Runner | None = None) -> dict[str, Any]:
    """List the interfaces ``tshark -D`` offers, bounded and availability-gated.

    Without tshark on ``PATH`` (and no injected runner) this returns an honest
    unavailable dict -- ``available: False`` with the install hint and the
    admin/Npcap note -- never a crash. With a runner, ``tshark -D`` runs once
    with a bounded timeout; numbered lines are parsed into
    ``{number, device, description}`` records capped at :data:`MAX_INTERFACES`.

    The ``capture_runner`` parameter is the test seam: an injected stand-in
    replaces ``subprocess.run`` entirely, so no offline test spawns a process.
    """
    if capture_runner is None and not tshark_available():
        return _unavailable(NET_UNAVAILABLE_MESSAGE)
    execute = capture_runner if capture_runner is not None else subprocess.run
    try:
        outcome = execute(
            ("tshark", "-D"),
            capture_output=True,
            text=True,
            timeout=TSHARK_LIST_TIMEOUT,
        )
    except FileNotFoundError:
        return _unavailable(
            NET_UNAVAILABLE_MESSAGE,
            ["tshark vanished between the PATH probe and the interface listing"],
        )
    except subprocess.TimeoutExpired:
        return _unavailable(
            NET_UNAVAILABLE_MESSAGE,
            [f"tshark -D exceeded its timeout of {TSHARK_LIST_TIMEOUT:g} seconds"],
        )
    code, stdout, stderr = _text_outcome(outcome)
    if code is None:
        raise AnalysisError(
            "the capture runner violated the injection contract: returncode "
            "must be an int"
        )
    if code != 0:
        detail = " ".join(str(stderr).split()) or "no stderr output"
        return _unavailable(
            f"tshark -D exited with code {code}: {detail}",
            ["the interface listing failed; live capture likely lacks Npcap/admin rights"],
        )
    interfaces: list[dict[str, Any]] = []
    warnings: list[str] = []
    truncated = False
    for line in stdout.splitlines():
        match = _INTERFACE_LINE_RE.match(line)
        if match is None:
            if line.strip():
                _note(warnings, f"unparsed tshark -D line dropped: {line.strip()[:80]}")
            continue
        device_text = match.group(2)
        desc_match = _INTERFACE_DESC_RE.match(device_text)
        if desc_match is not None:
            device, description = desc_match.group(1), desc_match.group(2)
        else:
            device, description = device_text, None
        interfaces.append(
            {"number": int(match.group(1)), "device": device, "description": description}
        )
        if len(interfaces) >= MAX_INTERFACES:
            truncated = True
            _note(
                warnings,
                f"interface limit {MAX_INTERFACES} reached; further entries dropped",
            )
            break
    return {
        "available": True,
        "count": len(interfaces),
        "interfaces": interfaces,
        "truncated": truncated,
        "message": None,
        "warnings": warnings,
        "evidence": Evidence(
            source=EVIDENCE_SOURCE,
            method="tshark -D",
            confidence=Confidence.HIGH,
            detail=f"{len(interfaces)} interface(s) listed on this machine",
        ).to_dict(),
    }

@dataclass(frozen=True)
class NetCaptureResult:
    """Everything one bounded capture-around-a-run produced, honestly.

    Attributes:
        available: ``False`` when the availability gate stopped everything
            before any process ran (pcap/target fields then stay ``None``).
        capture_seconds / interface: The requested capture window and the
            ``tshark -i`` argument actually used.
        pcap_path / pcap_bytes / pcap_sha256: Where tshark wrote the capture,
            its size and its full-stream digest (``None`` when no pcap exists).
        target_argv / target_exit_code: The exact target argv and its exit
            code (``None`` when the target's budget ended the run).
        target_stdout / target_stderr: The bounded decoded streams, reusing
            the proc lane's capture semantics (truncation flags included).
        target_timed_out / target_duration_ms: Whether the target hit its
            budget and how long the owned run took.
        pcap_summary: The offline :mod:`codevanta.analysis.tshark_bridge`
            read of the finished pcap, or ``None`` when unavailable.
        message: Human-readable note for the unavailable/degraded paths.
        warnings: Stage-named bounds and failures.
        evidence: ``net.capture`` / ``tshark-around-run`` at HIGH confidence
            for the observed facts (LOW for the availability-only path).
    """

    available: bool
    capture_seconds: int
    interface: str
    pcap_path: str | None = None
    pcap_bytes: int | None = None
    pcap_sha256: str | None = None
    target_argv: tuple[str, ...] = ()
    target_exit_code: int | None = None
    target_stdout: str = ""
    target_stderr: str = ""
    target_stdout_truncated: bool = False
    target_stderr_truncated: bool = False
    target_timed_out: bool = False
    target_duration_ms: float | None = None
    pcap_summary: dict[str, Any] | None = None
    message: str | None = None
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method=EVIDENCE_METHOD,
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result for the MCP payload (JSON-safe values only)."""
        return {
            "available": self.available,
            "capture_seconds": self.capture_seconds,
            "interface": self.interface,
            "pcap_path": self.pcap_path,
            "pcap_bytes": self.pcap_bytes,
            "pcap_sha256": self.pcap_sha256,
            "target_argv": list(self.target_argv),
            "target_exit_code": self.target_exit_code,
            "target_stdout": self.target_stdout,
            "target_stderr": self.target_stderr,
            "target_stdout_truncated": self.target_stdout_truncated,
            "target_stderr_truncated": self.target_stderr_truncated,
            "target_timed_out": self.target_timed_out,
            "target_duration_ms": self.target_duration_ms,
            "pcap_summary": self.pcap_summary,
            "message": self.message,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

def capture_around(
    command: str,
    arguments: Sequence[str] | None,
    capture_seconds: int,
    interface: str,
    output_directory: str | Path,
    *,
    proc_runner: ProcRunner | None = None,
    capture_runner: CaptureStarter | None = None,
    summary_runner: Runner | None = None,
) -> NetCaptureResult:
    """Record the network with tshark while the target command runs locally.

    SECURITY/HONESTY: the target is *executed* on this machine as an owned
    subprocess (the :func:`codevanta.analysis.proc_capture.capture_process`
    contract: argv form, pipes, output and wall clock bounded) and a background
    ``tshark`` records this machine's packets around it
    (``-a duration:<capture_seconds>`` auto-stops the capture). Live capture
    needs elevated privileges plus Npcap/WinPcap on Windows -- without them
    tshark may start yet record nothing, so the pcap summary stays empty and
    the warnings say so.

    The availability gate runs first: without tshark on ``PATH`` (and without
    injected runners) the honest unavailable :class:`NetCaptureResult` is
    returned and *nothing* is executed -- not even the target. Caller mistakes
    (out-of-range ``capture_seconds``, too many arguments, bad paths) are typed
    :class:`~codevanta.core.report.AnalysisError`\\ s before anything runs.

    The three keyword seams exist for the offline tests: ``capture_runner``
    replaces ``subprocess.Popen`` for the background tshark, ``proc_runner``
    replaces the target's ``subprocess.run``, ``summary_runner`` replaces the
    offline ``tshark -r`` summary read. No test ever spawns a real tshark.

    Raises:
        AnalysisError: Any input is out of bounds, or the tshark-start stage
            fails (the probe passed but the spawn did not).
    """
    checked_seconds = _check_capture_seconds(capture_seconds)
    checked_args = _check_arguments(arguments)
    checked_interface = _check_interface(interface)
    out_dir = _check_output_directory(output_directory)

    if capture_runner is None and summary_runner is None and not tshark_available():
        return NetCaptureResult(
            available=False,
            capture_seconds=checked_seconds,
            interface=checked_interface,
            message=NET_UNAVAILABLE_MESSAGE,
            evidence=Evidence(
                source=EVIDENCE_SOURCE,
                method="availability-probe",
                confidence=Confidence.LOW,
                detail="tshark is not on PATH; the target was NOT run",
            ),
        )

    warnings: list[str] = []
    number = _next_pcap_number()
    pcap_path = out_dir / f"net_capture_{number}.pcap"
    if pcap_path.exists():
        _note(warnings, f"overwriting an existing capture file: {pcap_path.name}")

    # Stage: tshark-start. The auto-stop flag keeps the capture bounded even
    # if the target hangs; devnull stderr avoids a blocked-pipe deadlock.
    tshark_argv = [
        "tshark",
        "-i",
        checked_interface,
        "-a",
        f"duration:{checked_seconds}",
        "-w",
        str(pcap_path),
        "-q",
    ]
    starter = capture_runner if capture_runner is not None else subprocess.Popen
    try:
        process = starter(
            tshark_argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"tshark-start stage failed: tshark vanished between the PATH probe "
            f"and the spawn ({exc})"
        ) from exc
    except OSError as exc:
        raise AnalysisError(f"tshark-start stage failed: {exc}") from exc
    if not callable(getattr(process, "wait", None)) or not callable(
        getattr(process, "kill", None)
    ):
        raise AnalysisError(
            "the capture runner violated the injection contract: the handle must "
            "provide callable wait() and kill()"
        )

    # The target runs concurrently (tshark is already recording); its capture
    # reuses the proc lane's contract and shares the capture window as budget.
    target: ProcCapture = capture_process(
        command,
        checked_args,
        timeout=float(checked_seconds),
        runner=proc_runner,
    )
    for message in target.warnings:
        _note(warnings, f"target: {message}")

    # Stage: tshark-join. Bounded: at most the window plus the grace period.
    tshark_code: int | None = None
    try:
        tshark_code = process.wait(
            timeout=float(checked_seconds) + TSHARK_JOIN_GRACE_SECONDS
        )
    except subprocess.TimeoutExpired:
        process.kill()
        _note(
            warnings,
            "tshark-join stage: tshark did not exit within its bounded join "
            "window and was killed; the pcap may be incomplete",
        )
    if isinstance(tshark_code, int) and tshark_code != 0:
        _note(
            warnings,
            f"tshark-exit stage: tshark exited with code {tshark_code} "
            "(a bad interface or missing Npcap/admin rights records nothing)",
        )

    pcap_bytes: int | None = None
    pcap_sha256: str | None = None
    summary: dict[str, Any] | None = None
    if pcap_path.is_file():
        pcap_bytes, pcap_sha256 = _digest_file(pcap_path)
        # Stage: summary. The offline bridge read path, never a live capture.
        try:
            summary = pcap_fields(
                pcap_path,
                list(SUMMARY_FIELDS),
                packet_limit=DEFAULT_PACKET_LIMIT,
                runner=summary_runner,
            ).to_dict()
        except AnalysisError as exc:
            _note(warnings, f"summary stage failed: {exc}")
    else:
        _note(
            warnings,
            f"pcap-missing stage: tshark wrote no capture file at {pcap_path.name}",
        )

    return NetCaptureResult(
        available=True,
        capture_seconds=checked_seconds,
        interface=checked_interface,
        pcap_path=str(pcap_path),
        pcap_bytes=pcap_bytes,
        pcap_sha256=pcap_sha256,
        target_argv=tuple(target.command),
        target_exit_code=target.exit_code,
        target_stdout=target.stdout,
        target_stderr=target.stderr,
        target_stdout_truncated=target.stdout_truncated,
        target_stderr_truncated=target.stderr_truncated,
        target_timed_out=target.timed_out,
        target_duration_ms=round(target.duration_ms, 3),
        pcap_summary=summary,
        message=None,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method=EVIDENCE_METHOD,
            confidence=Confidence.HIGH,
            detail=(
                f"recorded {checked_seconds}s on interface {checked_interface!r} "
                f"around argv[0]={command.strip()!r}; pcap "
                f"{pcap_bytes if pcap_bytes is not None else 0} byte(s)"
            ),
            extra={
                "capture_seconds": checked_seconds,
                "interface": checked_interface,
                "pcap_present": pcap_path.is_file(),
                "target_exit_code": target.exit_code,
                "target_timed_out": target.timed_out,
                "summary_present": summary is not None,
                "warning_count": len(warnings),
            },
        ),
    )







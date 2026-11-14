"""Live Frida instrumentation: device probes, process lists and script sessions.

The frida lane applies the adb/sigrok pattern to dynamic instrumentation:
everything that *understands* Frida's output is a pure, offline-tested parser
(:func:`parse_devices`, :func:`parse_processes`, :func:`parse_script_output`)
and everything that *runs* Frida is skip-gated on a dual probe -- the
``frida-ls-devices`` / ``frida-ps`` / ``frida`` CLIs on ``PATH`` (preferred:
no pyproject change) and the importable ``frida`` Python module. On a machine
with neither, every wrapper still imports and fails with one typed
:class:`~codevanta.core.report.AnalysisError` naming exactly what is missing.

Device and process probes shell out to the CLI with a bounded timeout and an
injectable runner (:class:`Runner`), so canned transcripts drive the whole
pipeline offline. :func:`start_session` owns a session lifecycle: with the
``frida`` module it attaches (or spawns) and keeps a :class:`FridaSession`
handle for :meth:`FridaSession.load_script`, :meth:`FridaSession.resume` and
:meth:`FridaSession.close`; without the module it degrades to one bounded
``frida -l <script>`` CLI run whose stdout console lines and ``send()`` JSON
payloads are captured up to :data:`MAX_MESSAGES`.

Everything is bounded by construction: message lists (max 200), script
sources (max 64 KiB), device/process lists, and the wall-clock budget (max
60 s). Junk transcript lines become warnings; malformed parser input raises
the typed error instead.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_DURATION",
    "DEFAULT_TIMEOUT",
    "EVIDENCE_SOURCE",
    "FRIDA_ONESHOT_MESSAGE",
    "FRIDA_SESSION_MISSING_MESSAGE",
    "MAX_DEVICES",
    "MAX_MESSAGES",
    "MAX_PROCESSES",
    "MAX_SCRIPT_BYTES",
    "MAX_TIMEOUT",
    "MAX_WARNINGS",
    "MODES",
    "MODE_ATTACH",
    "MODE_SPAWN",
    "FridaDevice",
    "FridaDevicesResult",
    "FridaMessage",
    "FridaMessageBatch",
    "FridaProcess",
    "FridaProcessesResult",
    "FridaScriptResult",
    "FridaSession",
    "Runner",
    "RunnerOutcome",
    "frida_available",
    "frida_cli_available",
    "frida_module_available",
    "frida_status",
    "list_devices",
    "list_processes",
    "parse_devices",
    "parse_processes",
    "parse_script_output",
    "start_session",
]

#: Evidence ``source`` id for this lane (``live.frida``).
EVIDENCE_SOURCE = "live.frida"

#: Session modes accepted by :func:`start_session`.
MODE_ATTACH = "attach"
MODE_SPAWN = "spawn"
MODES = (MODE_ATTACH, MODE_SPAWN)

#: Default wall-clock budget for one frida CLI probe, in seconds.
DEFAULT_TIMEOUT = 15.0

#: Default run duration for one bounded script session, in seconds.
DEFAULT_DURATION = 10.0

#: Hard ceiling on any frida wall-clock budget (probes and script runs).
MAX_TIMEOUT = 60.0

#: Devices kept from one ``frida-ls-devices`` transcript (bounded work).
MAX_DEVICES = 16

#: Processes kept from one ``frida-ps`` transcript (bounded work).
MAX_PROCESSES = 256

#: Script console/``send()`` messages captured per session (bounded work).
MAX_MESSAGES = 200

#: Hard ceiling on the size of a script :meth:`FridaSession.load_script` accepts.
MAX_SCRIPT_BYTES = 64 * 1024

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Typed failure for the CLI probes when a frida binary is absent.
FRIDA_CLI_MISSING = (
    "{binary} is not on PATH; install the frida CLI tools "
    "(pip install frida-tools, https://frida.re) and make sure they are on PATH"
)

#: Typed failure for :func:`start_session` when both gate halves are absent.
FRIDA_SESSION_MISSING_MESSAGE = (
    "frida is not available: the frida Python module is not installed and the "
    "frida CLI is not on PATH; install with pip install frida-tools "
    "(https://frida.re)"
)

#: Typed failure for the one-shot CLI session's deferred lifecycle calls.
FRIDA_ONESHOT_MESSAGE = (
    "this session came from the one-shot `frida` CLI fallback: the script "
    "already ran to its duration budget and the process was reaped; install "
    "the frida Python module (pip install frida) for interactive "
    "load_script/resume sessions"
)

#: Two-or-more spaces separate the columns of frida CLI tables.
_COLUMN_SPLIT = re.compile(r"\s{2,}")

#: Characters a frida device id or program name may contain before argv.
_TARGET_CHARS = re.compile(r"^[A-Za-z0-9._:+/@\\-]+$")

def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; summarised...")


def _as_text(text: Any) -> str:
    """Validate parser input: one transcript is a ``str``, nothing else."""
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    return text


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat


def _check_timeout(timeout: Any) -> float:
    """Validate a wall-clock budget (probes and script runs)."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AnalysisError(f"timeout must be a positive number of seconds, got {timeout!r}")
    if not 1.0 <= float(timeout) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(timeout)


def _check_duration(duration: Any) -> float:
    """Validate one bounded script-run duration against :data:`MAX_TIMEOUT`."""
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration <= 0:
        raise AnalysisError(f"duration must be a positive number of seconds, got {duration!r}")
    if not 1.0 <= float(duration) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"duration {duration} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(duration)


def _check_target(target: Any) -> int | str:
    """Validate the session target: a positive pid or a program name."""
    if isinstance(target, bool):
        raise AnalysisError("target must be a positive pid or a program name, not a bool")
    if isinstance(target, int):
        if target <= 0:
            raise AnalysisError(f"target pid must be positive, got {target}")
        return target
    if isinstance(target, str):
        text = target.strip()
        if not text:
            raise AnalysisError("target program name must not be empty")
        if len(text) > 256:
            raise AnalysisError("target is longer than 256 characters")
        if not _TARGET_CHARS.match(text):
            raise AnalysisError(
                f"target {text!r} contains characters frida does not accept; expected "
                "alphanumerics plus . _ : + / @ \\ -"
            )
        return text
    raise AnalysisError(f"target must be a pid or a program name, got {type(target).__name__}")


def _check_mode(mode: Any, target: int | str) -> str:
    """Validate the session mode and its target-kind pairing."""
    if not isinstance(mode, str) or mode.strip().lower() not in MODES:
        raise AnalysisError(f"mode must be one of {', '.join(MODES)}, got {mode!r}")
    checked = mode.strip().lower()
    if checked == MODE_SPAWN and isinstance(target, int):
        raise AnalysisError(
            "spawn mode needs a program name; attach mode accepts a pid or a name"
        )
    return checked


def _check_device_id(device_id: Any) -> str | None:
    """Validate an optional frida device id before it reaches argv."""
    if device_id is None:
        return None
    if not isinstance(device_id, str):
        raise AnalysisError(f"device_id must be a string, got {type(device_id).__name__}")
    text = device_id.strip()
    if not text:
        raise AnalysisError("device_id must not be empty")
    if len(text) > 128 or not _TARGET_CHARS.match(text):
        raise AnalysisError(
            f"device_id {text!r} is not a frida device id; expected alphanumerics "
            "plus . _ : + / @ \\ -"
        )
    return text


def _read_script(source_file: Any) -> str:
    """Read one gadget script, bounded to :data:`MAX_SCRIPT_BYTES`."""
    if not isinstance(source_file, (str, Path)):
        raise AnalysisError(
            f"source_file must be a str or Path, got {type(source_file).__name__}"
        )
    path = Path(source_file)
    if not path.is_file():
        raise AnalysisError(f"script file not found: {path}")
    size = path.stat().st_size
    if size > MAX_SCRIPT_BYTES:
        raise AnalysisError(
            f"script is {size} bytes; expected at most {MAX_SCRIPT_BYTES} (64 KiB): {path}"
        )
    return path.read_text(encoding="utf-8")


def _import_frida() -> Any | None:
    """Import the frida Python module, ``None`` when it is not installed."""
    try:
        import frida  # noqa: PLC0415 -- deliberate lazy import (the dual gate)
    except ImportError:
        return None
    return frida


def _which(binary: str) -> str | None:
    """Probe ``PATH`` for one frida CLI binary; nothing else can fail."""
    return shutil.which(binary)


def frida_cli_available() -> bool:
    """Report whether the frida CLI tools are on ``PATH``."""
    return _which("frida") is not None or _which("frida-ps") is not None


def frida_module_available() -> bool:
    """Report whether the ``frida`` Python module is importable."""
    return _import_frida() is not None


def frida_available() -> bool:
    """Dual gate: CLI tools or the Python module; the caller needs only this."""
    return frida_cli_available() or frida_module_available()


def frida_status() -> dict[str, bool]:
    """Report both gate halves so callers can explain *why* frida is missing."""
    cli = frida_cli_available()
    module = frida_module_available()
    return {"cli": cli, "module": module, "available": cli or module}


def _require_cli(binary: str, label: str) -> None:
    """Raise the typed skip-gate failure when a frida binary is absent."""
    if _which(binary) is None:
        raise AnalysisError(FRIDA_CLI_MISSING.format(binary=binary) + f" ({label})")


@dataclass(frozen=True)
class FridaMessage:
    """One script message: a ``send()``/``error`` payload or a console log line."""

    kind: str
    payload: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "payload": self.payload}


@dataclass(frozen=True)
class FridaMessageBatch:
    """Bounded message batch parsed from one script-run transcript."""

    messages: tuple[FridaMessage, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FridaDevice:
    """One row of ``frida-ls-devices`` output."""

    device_id: str
    kind: str
    name: str
    os: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.device_id,
            "type": self.kind,
            "name": self.name,
        }
        if self.os:
            data["os"] = self.os
        return data


@dataclass(frozen=True)
class FridaDevicesResult:
    """Bounded device list from one ``frida-ls-devices`` transcript."""

    devices: tuple[FridaDevice, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="frida-ls-devices",
            confidence=Confidence.MEDIUM,
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
class FridaProcess:
    """One row of ``frida-ps`` output (identifier only with ``-a`` transcripts)."""

    pid: int
    name: str
    identifier: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"pid": self.pid, "name": self.name}
        if self.identifier:
            data["identifier"] = self.identifier
        return data


@dataclass(frozen=True)
class FridaProcessesResult:
    """Bounded process list from one ``frida-ps`` transcript."""

    processes: tuple[FridaProcess, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="frida-ps",
            confidence=Confidence.MEDIUM,
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
class FridaScriptResult:
    """Record of one finished bounded script run (one-shot CLI fallback)."""

    target: str
    mode: str
    device_id: str | None
    script_path: str
    duration: float
    messages: tuple[FridaMessage, ...]
    truncated: bool
    timeout_reached: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="frida -l script",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "device_id": self.device_id,
            "script_path": self.script_path,
            "duration": self.duration,
            "messages": [message.to_dict() for message in self.messages],
            "message_count": len(self.messages),
            "truncated": self.truncated,
            "timeout_reached": self.timeout_reached,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_devices(text: str) -> FridaDevicesResult:
    """Parse one ``frida-ls-devices`` transcript into a bounded device list.

    Rows are ``id  type  name  os`` columns split on two-or-more spaces; the
    header and the dash rule are skipped, junk rows become warnings.
    """
    raw = _as_text(text)
    warnings: list[str] = []
    devices: list[FridaDevice] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " "}:
            continue
        parts = _COLUMN_SPLIT.split(stripped)
        if parts[0].lower() == "id":
            continue
        if len(parts) >= 4:
            devices.append(FridaDevice(parts[0], parts[1], parts[2], parts[3]))
        elif len(parts) >= 3:
            devices.append(FridaDevice(parts[0], parts[1], parts[2], None))
        else:
            _note(warnings, f"skipping unrecognised frida-ls-devices row: {stripped[:80]}")
    truncated = len(devices) > MAX_DEVICES
    if truncated:
        _note(warnings, f"more than {MAX_DEVICES} devices; kept the first {MAX_DEVICES}")
    return FridaDevicesResult(
        devices=tuple(devices[:MAX_DEVICES]),
        truncated=truncated,
        warnings=warnings,
    )


def parse_processes(text: str) -> FridaProcessesResult:
    """Parse one ``frida-ps`` transcript into a bounded process list.

    Rows are ``pid  name`` (plus an ``identifier`` column in ``-a``/application
    transcripts); the header and dash rule are skipped, non-numeric pids and
    other junk rows become warnings.
    """
    raw = _as_text(text)
    warnings: list[str] = []
    processes: list[FridaProcess] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " "}:
            continue
        parts = _COLUMN_SPLIT.split(stripped)
        if parts[0].upper() == "PID":
            continue
        if len(parts) >= 2 and parts[0].isdigit():
            identifier = parts[2] if len(parts) >= 3 else None
            processes.append(FridaProcess(int(parts[0]), parts[1], identifier))
        else:
            _note(warnings, f"skipping unrecognised frida-ps row: {stripped[:80]}")
    truncated = len(processes) > MAX_PROCESSES
    if truncated:
        _note(warnings, f"more than {MAX_PROCESSES} processes; kept the first {MAX_PROCESSES}")
    return FridaProcessesResult(
        processes=tuple(processes[:MAX_PROCESSES]),
        truncated=truncated,
        warnings=warnings,
    )


def parse_script_output(text: str) -> FridaMessageBatch:
    """Parse one script-run transcript into a bounded message batch.

    A line that is itself a JSON object with a string ``type`` becomes a
    structured message (``send``, ``error``); every other non-blank line
    becomes a console ``log`` message. Beyond :data:`MAX_MESSAGES` the rest
    is summarised away as a warning.
    """
    raw = _as_text(text)
    warnings: list[str] = []
    messages: list[FridaMessage] = []
    dropped = 0
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        message = _message_from_line(stripped)
        if len(messages) >= MAX_MESSAGES:
            dropped += 1
            continue
        messages.append(message)
    if dropped:
        _note(warnings, f"{dropped} more messages beyond the {MAX_MESSAGES} cap; summarised")
    return FridaMessageBatch(
        messages=tuple(messages),
        truncated=bool(dropped),
        warnings=warnings,
    )


def _message_from_line(line: str) -> FridaMessage:
    """Turn one transcript line into a structured message or a log line.

    The frida CLI prefixes messages with a target tag (``[App::pid]-> {..}``),
    so the JSON object may start mid-line; a line that contains a JSON object
    with a string ``type`` becomes a structured message.
    """
    brace = line.find("{")
    if brace >= 0 and line.rstrip().endswith("}"):
        try:
            payload = json.loads(line[brace:])
        except ValueError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("type"), str):
            inner = payload.get("payload")
            if isinstance(inner, str):
                rendered = inner
            elif inner is None:
                rendered = ""
            else:
                rendered = json.dumps(inner, sort_keys=True, default=str)
            return FridaMessage(kind=payload["type"], payload=rendered)
    return FridaMessage(kind="log", payload=line)


class FridaSession:
    """A live Frida session, or the record of a finished one-shot CLI run.

    Module-backed sessions are created by :func:`start_session` and expose the
    typed lifecycle: :meth:`load_script` (bounded to 64 KiB), :meth:`resume`
    (only meaningful for a spawned process) and :meth:`close` (always safe).
    The session is a context manager: leaving it closes it, so an exception in
    the middle of a session cannot leak a target process.
    """

    def __init__(
        self,
        *,
        target: int | str,
        mode: str,
        device_id: str | None,
        module_device: Any | None = None,
        module_session: Any | None = None,
        spawned_pid: int | None = None,
        result: FridaScriptResult | None = None,
    ) -> None:
        self._device = module_device
        self._session = module_session
        self._script: Any | None = None
        self._spawned_pid = spawned_pid
        self._messages: deque[FridaMessage] = deque(maxlen=MAX_MESSAGES)
        self._dropped = 0
        self.target = target
        self.mode = mode
        self.device_id = device_id
        self.resumed = False
        self.closed = False
        self.result = result

    @property
    def one_shot(self) -> bool:
        """True when this handle wraps a finished one-shot CLI run."""
        return self._session is None

    @property
    def messages(self) -> tuple[FridaMessage, ...]:
        """The messages captured so far, bounded to :data:`MAX_MESSAGES`."""
        return tuple(self._messages)

    @property
    def dropped_messages(self) -> int:
        """How many messages were summarised away by the cap."""
        return self._dropped

    def _on_message(self, message: Any, _data: Any) -> None:
        """Collector for the frida module's ``script.on('message', ...)``."""
        kind = message.get("type") if isinstance(message, dict) else None
        payload = message.get("payload") if isinstance(message, dict) else None
        kind_text = kind if isinstance(kind, str) else "log"
        if isinstance(payload, str):
            payload_text: str = payload
        elif payload is None:
            payload_text = ""
        else:
            payload_text = json.dumps(payload, sort_keys=True, default=str)
        if len(self._messages) >= MAX_MESSAGES:
            self._dropped += 1
            return
        self._messages.append(FridaMessage(kind=kind_text, payload=payload_text))

    def load_script(self, source_file: str | Path) -> int:
        """Load one bounded script into the live session; return message count."""
        if self._session is None:
            raise AnalysisError(FRIDA_ONESHOT_MESSAGE)
        if self.closed:
            raise AnalysisError(
                "the Frida session is already closed; start a new one to load another script"
            )
        source = _read_script(source_file)
        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self._script = script
        return len(self._messages)

    def run_for(self, duration: float = DEFAULT_DURATION) -> int:
        """Collect messages for a bounded wall-clock slice; return the count."""
        checked = _check_duration(duration)
        if self.closed:
            raise AnalysisError("the Frida session is already closed; nothing to wait for")
        deadline = time.monotonic() + checked
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
        return len(self._messages)

    def resume(self) -> None:
        """Resume a spawned target; a no-op mark for attach-mode sessions."""
        if self._session is None:
            raise AnalysisError(FRIDA_ONESHOT_MESSAGE)
        if self.closed:
            raise AnalysisError("the Frida session is already closed; cannot resume")
        device = self._device
        if self._spawned_pid is not None and not self.resumed and device is not None:
            device.resume(self._spawned_pid)
        self.resumed = True

    def close(self) -> None:
        """Unload the script and detach, best-effort; idempotent and safe."""
        if self.closed or self._session is None:
            self.closed = True
            return
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:  # noqa: BLE001 -- shutdown is best-effort
                pass
        try:
            self._session.detach()
        except Exception:  # noqa: BLE001 -- shutdown is best-effort
            pass
        self.closed = True

    def __enter__(self) -> FridaSession:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe snapshot of the handle (plus the one-shot record, if any)."""
        data: dict[str, Any] = {
            "target": str(self.target),
            "mode": self.mode,
            "device_id": self.device_id,
            "one_shot": self.one_shot,
            "resumed": self.resumed,
            "closed": self.closed,
            "messages": [message.to_dict() for message in self._messages],
            "message_count": len(self._messages),
            "dropped_messages": self._dropped,
        }
        if self.result is not None:
            data["result"] = self.result.to_dict()
        return data


class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped."""

    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> RunnerOutcome: ...


def _run_cli(
    command: tuple[str, ...],
    *,
    timeout: float,
    runner: Runner | None,
    label: str,
    timeout_is_budget: bool = False,
) -> tuple[int, str, str]:
    """Run one frida CLI command, bounded, -> ``(returncode, stdout, stderr)``.

    With ``timeout_is_budget`` (the one-shot script run) a
    :class:`subprocess.TimeoutExpired` is the *expected* end of the bounded
    duration: the output gathered so far is returned with sentinel code 124
    instead of raising. With the default runner the typed missing-binary
    failure fires before anything is spawned; an injected ``runner`` stands in
    for ``subprocess.run`` entirely, so the PATH probe is skipped and the
    pipeline runs offline against canned output.
    """
    if runner is None:
        _require_cli(command[0], label)
    checked = _check_timeout(timeout)
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked)
    except subprocess.TimeoutExpired as exc:
        if timeout_is_budget:
            raw: bytes | str | None = exc.stdout
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            return 124, (raw if isinstance(raw, str) else ""), ""
        raise AnalysisError(
            f"{label} exceeded its timeout of {checked} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{FRIDA_CLI_MISSING.format(binary=command[0])} ({label}); the executable "
            "vanished between the PATH probe and the call"
        ) from exc
    returncode = getattr(outcome, "returncode", None)
    if not isinstance(returncode, int):
        raise AnalysisError(
            "the runner outcome violates the injection contract: returncode must be an int"
        )
    stdout = getattr(outcome, "stdout", None)
    stderr = getattr(outcome, "stderr", None)
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr if isinstance(stderr, str) else str(stderr or "")
    return returncode, stdout if isinstance(stdout, str) else "", stderr_text


def list_devices(
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> FridaDevicesResult:
    """Run ``frida-ls-devices`` and return the parsed, bounded device list."""
    code, out, err = _run_cli(
        ("frida-ls-devices",), timeout=timeout, runner=runner, label="frida-ls-devices"
    )
    if code != 0:
        raise AnalysisError(f"frida-ls-devices exited with code {code}: {_tail(err) or 'no stderr output'}")
    return parse_devices(out)


def list_processes(
    device_id: str | None = None,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> FridaProcessesResult:
    """Run ``frida-ps`` (``-D <id>`` with a device) and parse the list."""
    checked_device = _check_device_id(device_id)
    command: tuple[str, ...] = ("frida-ps",)
    if checked_device is not None:
        command = (*command, "-D", checked_device)
    code, out, err = _run_cli(command, timeout=timeout, runner=runner, label="frida-ps")
    if code != 0:
        raise AnalysisError(f"frida-ps exited with code {code}: {_tail(err) or 'no stderr output'}")
    return parse_processes(out)


def start_session(
    target: int | str,
    mode: str = MODE_ATTACH,
    *,
    device_id: str | None = None,
    script_path: str | Path | None = None,
    duration: float = DEFAULT_DURATION,
    module: Any | None = None,
    runner: Runner | None = None,
) -> FridaSession:
    """Start a Frida session on ``target`` (a pid or a program name).

    With the ``frida`` Python module (imported, or injected via ``module`` for
    tests and embedding hosts) this returns a live :class:`FridaSession` for
    the typed load_script/resume/close lifecycle. Without the module it
    degrades to one bounded ``frida -l <script>`` CLI run: ``script_path``
    becomes required, the run is capped at ``duration`` seconds (max
    :data:`MAX_TIMEOUT`), its stdout messages are captured, and the returned
    handle is a one-shot whose lifecycle methods raise the typed one-shot
    error. With neither the module nor the CLI, the typed
    :data:`FRIDA_SESSION_MISSING_MESSAGE` error fires before anything runs.
    """
    checked_target = _check_target(target)
    checked_mode = _check_mode(mode, checked_target)
    checked_device = _check_device_id(device_id)
    checked_duration = _check_duration(duration)
    if module is None:
        module = _import_frida()
    if module is not None:
        return _module_session(module, checked_target, checked_mode, checked_device)
    return _cli_session(
        checked_target,
        checked_mode,
        checked_device,
        script_path=script_path,
        duration=checked_duration,
        runner=runner,
    )


def _module_session(
    module: Any,
    target: int | str,
    mode: str,
    device_id: str | None,
) -> FridaSession:
    """Open the live module session (attach or spawn) behind typed errors."""
    try:
        device = module.get_device(device_id) if device_id else module.get_local_device()
    except Exception as exc:  # noqa: BLE001 -- surfaced as one typed error
        raise AnalysisError(f"frida refused to open device {device_id or 'local'}: {exc}") from exc
    try:
        if mode == MODE_SPAWN:
            assert isinstance(target, str)  # noqa: S101 -- guaranteed by _check_mode
            pid = int(device.spawn([target]))
            session = device.attach(pid)
            return FridaSession(
                target=target,
                mode=mode,
                device_id=device_id,
                module_device=device,
                module_session=session,
                spawned_pid=pid,
            )
        session = device.attach(target)
    except AnalysisError:
        raise
    except Exception as exc:  # noqa: BLE001 -- surfaced as one typed error
        raise AnalysisError(
            f"frida refused to {mode} on {target!r}: {exc}"
        ) from exc
    return FridaSession(
        target=target,
        mode=mode,
        device_id=device_id,
        module_device=device,
        module_session=session,
    )


def _cli_session(
    target: int | str,
    mode: str,
    device_id: str | None,
    *,
    script_path: str | Path | None,
    duration: float,
    runner: Runner | None,
) -> FridaSession:
    """Run the bounded one-shot ``frida -l`` fallback and capture messages."""
    if script_path is None:
        raise AnalysisError(
            "the CLI fallback runs one bounded `frida -l <script>` invocation; "
            "pass script_path (or install the frida Python module for live sessions)"
        )
    checked_duration = _check_duration(duration)
    _read_script(script_path)
    if runner is None and _which("frida") is None and _import_frida() is None:
        raise AnalysisError(FRIDA_SESSION_MISSING_MESSAGE)
    command = ["frida"]
    if device_id is not None:
        command.extend(("-D", device_id))
    if mode == MODE_SPAWN:
        command.extend(("-f", str(target)))
    command.extend(("-l", str(script_path)))
    if mode == MODE_ATTACH:
        command.append(str(target))
    code, out, err = _run_cli(
        tuple(command),
        timeout=checked_duration,
        runner=runner,
        label=f"frida -l {Path(script_path).name}",
        timeout_is_budget=True,
    )
    batch = parse_script_output(out)
    warnings = list(batch.warnings)
    timeout_reached = code == 124
    if code not in (0, 124):
        raise AnalysisError(
            f"frida -l exited with code {code} after {checked_duration} seconds: "
            f"{_tail(err) or 'no stderr output'}"
        )
    result = FridaScriptResult(
        target=str(target),
        mode=mode,
        device_id=device_id,
        script_path=str(script_path),
        duration=checked_duration,
        messages=batch.messages,
        truncated=batch.truncated,
        timeout_reached=timeout_reached,
        warnings=warnings,
    )
    session = FridaSession(target=target, mode=mode, device_id=device_id, result=result)
    for message in batch.messages:
        session._messages.append(message)  # already capped by parse_script_output
    return session


"""Wakaru wrapper: pure output parser plus one skip-gated live recovery.

Wakaru (``@wakaru/cli``, a Node tool) turns bundled/minified JavaScript back
into readable modules. The same pattern as the adb/sigrok/apktool lanes:
everything that *understands* wakaru is the pure :func:`parse_wakaru_output`
function, fully tested offline against canned transcripts, and everything
that *runs* wakaru is :func:`js_recover`, gated on one availability probe --
``wakaru --version`` on ``PATH`` or, failing that, an ``npx --no-install``
detection -- with a bounded timeout and an injectable runner for offline
tests. On a machine without Node the parser still runs and the wrapper still
imports; it fails with the typed
:class:`~codevanta.core.report.AnalysisError` naming the
``npm i -g @wakaru/cli`` install hint -- never a traceback, never a partial
recovery.

Two modes: ``minify`` (wakaru's ``unminify`` verb: restore readable
identifiers from minified code) and ``unpack`` (split a webpack-style bundle
back into per-module files). Recovered entries are kept up to
:data:`MAX_ENTRIES`; junk lines become warnings.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_TIMEOUT",
    "EVIDENCE_SOURCE",
    "MAX_ENTRIES",
    "MAX_TIMEOUT",
    "MODES",
    "MODE_MINIFY",
    "MODE_UNPACK",
    "RecoveredEntry",
    "WAKARU_MISSING_MESSAGE",
    "WakaruConsole",
    "WakaruRecoverResult",
    "js_recover",
    "parse_wakaru_output",
    "wakaru_available",
]

#: Default wall-clock budget for one wakaru invocation, in seconds.
DEFAULT_TIMEOUT = 120.0

#: Hard ceiling on the wall-clock budget of one wakaru invocation.
MAX_TIMEOUT = 300.0

#: Recovered entries kept from one transcript (bounded work).
MAX_ENTRIES = 64

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "bridge.wakaru"

#: ``minify`` maps onto wakaru's ``unminify`` verb; ``unpack`` is verbatim.
MODE_MINIFY = "minify"
MODE_UNPACK = "unpack"
MODES = (MODE_MINIFY, MODE_UNPACK)
_SUBCOMMANDS = {MODE_MINIFY: "unminify", MODE_UNPACK: "unpack"}

#: Typed failure when wakaru is unavailable, naming the npm install hint.
WAKARU_MISSING_MESSAGE = (
    "wakaru (@wakaru/cli) is not available; install it with "
    "`npm i -g @wakaru/cli` (requires Node.js) and make sure it is on PATH"
)

#: ``dist/app.min.js -> out/app.js (done in 0.4s)`` -- one recovered file row.
_ARROW_ROW = re.compile(
    r"^(?P<source>.+?)\s+->\s+(?P<target>\S+)(?:\s+\((?P<note>[^()]*)\))?$"
)

#: ``12 modules written to out/`` -- a module-count line.
_MODULE_COUNT = re.compile(r"(?P<count>\d+)\s+module", re.IGNORECASE)

#: ``packer type: webpack`` / ``packer: webpack`` -- the detected packer.
_PACKER = re.compile(r"packer(?:\s+type)?[:=]\s*(?P<packer>[A-Za-z0-9_.-]+)")


class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped."""

    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> RunnerOutcome: ...

def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat


@dataclass(frozen=True)
class RecoveredEntry:
    """One recovered file row: source bundle member -> recovered output."""

    source: str
    target: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, str]:
        data: dict[str, str] = {"source": self.source}
        if self.target is not None:
            data["target"] = self.target
        if self.note is not None:
            data["note"] = self.note
        return data


@dataclass(frozen=True)
class WakaruConsole:
    """Bounded, evidence-backed parse of one wakaru console transcript."""

    entries: tuple[RecoveredEntry, ...] = ()
    module_count: int | None = None
    packer: str | None = None
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="parse_wakaru_output",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "count": len(self.entries),
            "module_count": self.module_count,
            "packer": self.packer,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _check_mode(value: Any) -> str:
    """Validate one recovery mode; the wrapper and parser share the bound."""
    if not isinstance(value, str):
        raise AnalysisError(f"mode must be a string, got {type(value).__name__}")
    mode = value.strip().lower()
    if mode not in MODES:
        raise AnalysisError(f"invalid mode {value!r}; expected one of {', '.join(MODES)}")
    return mode


def parse_wakaru_output(text: Any, mode: str = MODE_MINIFY) -> WakaruConsole:
    """Parse wakaru console output into bounded typed recovery entries.

    ``<source> -> <target> (note)`` lines become :class:`RecoveredEntry`
    records; ``N modules`` lines set ``module_count``; ``packer type: X``
    lines set ``packer``. Everything else is chatter and becomes a warning.
    The parse itself never raises for transcript content; a non-``str``
    transcript or an invalid ``mode`` raises the typed error.
    """
    _check_mode(mode)  # validated only; the parse itself is mode-independent
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    entries: list[RecoveredEntry] = []
    warnings: list[str] = []
    truncated = False
    module_count: int | None = None
    packer: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        row = _ARROW_ROW.match(stripped)
        if row is not None:
            if len(entries) >= MAX_ENTRIES:
                truncated = True
                _note(warnings, f"entry limit {MAX_ENTRIES} reached; further rows dropped")
                break
            entries.append(
                RecoveredEntry(
                    source=row.group("source").strip(),
                    target=row.group("target"),
                    note=row.group("note"),
                )
            )
            continue
        if module_count is None:
            counted = _MODULE_COUNT.search(stripped)
            if counted is not None:
                module_count = int(counted.group("count"))
                continue
        if packer is None:
            named = _PACKER.search(stripped)
            if named is not None:
                packer = named.group("packer")
                continue
        _note(warnings, f"unrecognised line skipped: {stripped[:64]!r}")
    if not entries and not warnings:
        _note(warnings, "no wakaru output lines in the transcript")
    return WakaruConsole(
        entries=tuple(entries),
        module_count=module_count,
        packer=packer,
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="parse_wakaru_output",
            confidence=Confidence.MEDIUM,
            detail=f"{len(entries)} recovered entry(ies), mode={mode}",
        ),
    )

@dataclass(frozen=True)
class WakaruRecoverResult:
    """Typed result of one skip-gated wakaru recovery run."""

    bundle: str
    out_dir: str
    mode: str
    entries: tuple[RecoveredEntry, ...] = ()
    module_count: int | None = None
    packer: str | None = None
    truncated: bool = False
    command: str = ""
    transcript_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="js_recover",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle,
            "out_dir": self.out_dir,
            "mode": self.mode,
            "entries": [entry.to_dict() for entry in self.entries],
            "count": len(self.entries),
            "module_count": self.module_count,
            "packer": self.packer,
            "truncated": self.truncated,
            "command": self.command,
            "transcript_path": self.transcript_path,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _wakaru_binary() -> str | None:
    """Probe ``PATH`` for the wakaru binary."""
    return shutil.which("wakaru")


def _npx_available() -> bool:
    """Whether ``npx`` exists to try an ``--no-install`` wakaru detection."""
    return shutil.which("npx") is not None


def wakaru_available(*, runner: Runner | None = None, timeout: float = 30.0) -> bool:
    """Report whether wakaru can run on this machine.

    ``wakaru --version`` on ``PATH`` wins. Otherwise, when ``npx`` exists, one
    bounded ``npx --no-install wakaru --version`` probe decides. Every probe
    failure (missing binary, timeout, nonzero exit) is a plain ``False`` --
    availability probing never raises.
    """
    if _wakaru_binary() is not None:
        return True
    if _npx_available():
        command = ("npx", "--no-install", "wakaru", "--version")
        execute = runner if runner is not None else subprocess.run
        try:
            outcome = execute(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return False
        returncode = getattr(outcome, "returncode", None)
        return isinstance(returncode, int) and returncode == 0
    return False


def _check_timeout(value: Any) -> float:
    """Validate one wall-clock budget; the wrapper shares the bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"timeout must be a number of seconds, got {value!r}")
    timeout = float(value)
    if not 1.0 <= timeout <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return timeout


def _check_path(value: Any, role: str) -> Path:
    """Validate one ``str | Path`` argument and return it as a ``Path``."""
    if not isinstance(value, (str, Path)):
        raise AnalysisError(f"{role} must be a str or Path, got {type(value).__name__}")
    return Path(value)


def _resolve_command(mode: str, bundle: Path, out_dir: Path) -> tuple[str, ...]:
    """Build the argv for ``mode``: the wakaru binary, or the npx fallback."""
    verb = _SUBCOMMANDS[mode]
    if _wakaru_binary() is not None:
        return ("wakaru", verb, str(bundle), "-o", str(out_dir))
    return ("npx", "--no-install", "wakaru", verb, str(bundle), "-o", str(out_dir))


def js_recover(
    bundle_path: str | Path,
    out_dir: str | Path,
    mode: str = MODE_MINIFY,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> WakaruRecoverResult:
    """Run wakaru over one JS bundle and parse its transcript.

    Skip-gated: without wakaru (binary or ``npx --no-install`` detection) and
    without an injected ``runner``, this raises the typed
    :data:`WAKARU_MISSING_MESSAGE` error before any process is spawned.
    ``mode='minify'`` runs wakaru's ``unminify`` verb; ``mode='unpack'``
    splits a bundled file into per-module outputs. The console transcript is
    preserved at ``<out_dir>/wakaru-<mode>.txt`` and parsed into a bounded
    :class:`RecoveredEntry` list.
    """
    checked_mode = _check_mode(mode)
    target = _check_path(bundle_path, "bundle_path")
    if not target.is_file():
        raise AnalysisError(f"bundle file not found: {target}")
    destination = _check_path(out_dir, "out_dir")
    checked_timeout = _check_timeout(timeout)
    if runner is None and not wakaru_available():
        raise AnalysisError(WAKARU_MISSING_MESSAGE)
    destination.mkdir(parents=True, exist_ok=True)
    command = _resolve_command(checked_mode, target, destination)
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked_timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"wakaru {checked_mode} exceeded its timeout of "
            f"{checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{WAKARU_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
            "executable vanished between the probe and the call"
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
    if returncode != 0:
        raise AnalysisError(
            f"wakaru exited with code {returncode}: {_tail(stderr_text) or 'no stderr output'}"
        )
    transcript_text = stdout if isinstance(stdout, str) else ""
    transcript = destination / f"wakaru-{checked_mode}.txt"
    transcript.write_text(transcript_text, encoding="utf-8")
    console = parse_wakaru_output(transcript_text, checked_mode)
    return WakaruRecoverResult(
        bundle=str(target),
        out_dir=str(destination),
        mode=checked_mode,
        entries=console.entries,
        module_count=console.module_count,
        packer=console.packer,
        truncated=console.truncated,
        command=" ".join(command),
        transcript_path=str(transcript),
        warnings=console.warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method=f"wakaru {_SUBCOMMANDS[checked_mode]}",
            confidence=Confidence.MEDIUM,
            detail=(
                f"{len(console.entries)} recovered entry(ies)"
                + (f", {console.module_count} modules" if console.module_count else "")
            ),
        ),
    )

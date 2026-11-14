"""rizin probes: bounded function listing and binary info key/value reports.

The adb/sigrok pattern applied to rizin: everything that *understands* rizin's
output is a pure parser (:func:`parse_afl`, :func:`parse_ii`) tested offline
against canned transcripts, and everything that *runs* rizin is skip-gated on
one ``shutil.which("rizin")`` probe and shells out with a bounded timeout and
an injectable :class:`Runner`. :func:`functions_of` runs ``rizin -q -c "aaa;
afl"`` and keeps a bounded function list (max :data:`MAX_FUNCTIONS`: address,
size, name); :func:`info_of` runs ``rizin -q -c iI`` and keeps the key/value
identity report (max :data:`MAX_INFO_FIELDS` fields). On a machine without
rizin -- a Windows workstation, a slim CI container -- the parsers still run
and the wrappers still import; they only ever fail with the typed
:class:`~codevanta.core.report.AnalysisError` carrying the install hint.
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
    "MAX_FUNCTIONS",
    "MAX_INFO_FIELDS",
    "MAX_TIMEOUT",
    "MAX_WARNINGS",
    "RIZIN_MISSING_MESSAGE",
    "Runner",
    "RunnerOutcome",
    "RizinFunction",
    "RizinFunctionsResult",
    "RizinInfoResult",
    "functions_of",
    "info_of",
    "parse_afl",
    "parse_ii",
    "rizin_available",
]

#: Evidence ``source`` id for this lane (``live.rizin``).
EVIDENCE_SOURCE = "live.rizin"

#: Default wall-clock budget for one rizin invocation, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one rizin invocation.
MAX_TIMEOUT = 120.0

#: Functions kept from one ``afl`` transcript (bounded work).
MAX_FUNCTIONS = 256

#: Key/value fields kept from one ``iI`` transcript (bounded work).
MAX_INFO_FIELDS = 64

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: ``0x00001060`` -- the leading address token of an ``afl`` row.
_ADDRESS_TOKEN = re.compile(r"^0x[0-9a-fA-F]+$")

#: ``arch     x86`` -- one ``iI`` key/value row.
_INFO_LINE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_.-]*)\s+(?P<value>\S.*?)\s*$")

#: Typed failure for every wrapper when rizin is absent, with the install hint.
RIZIN_MISSING_MESSAGE = (
    "rizin is not on PATH; install rizin (https://rizin.re) or radare2 "
    "(https://rada.re) and make sure rizin is on PATH"
)


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
        warnings.append(f"{MAX_WARNINGS}+ warnings; summarised...")


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat


def _check_timeout(timeout: Any) -> float:
    """Validate the wall-clock budget of one rizin invocation."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AnalysisError(f"timeout must be a positive number of seconds, got {timeout!r}")
    if not 1.0 <= float(timeout) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(timeout)


def _check_path(path: Any) -> Path:
    """Validate the analysed file exists before any process is spawned."""
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    return target


def _rizin_path() -> str | None:
    """Probe ``PATH`` for rizin; nothing else can fail."""
    return shutil.which("rizin")


def rizin_available() -> bool:
    """Report whether rizin is on ``PATH``; the only gate a caller needs."""
    return _rizin_path() is not None


def _require_rizin() -> None:
    """Raise the typed skip-gate failure when rizin is absent."""
    if _rizin_path() is None:
        raise AnalysisError(RIZIN_MISSING_MESSAGE)


def _run_rizin(
    script: str,
    target: Path,
    *,
    timeout: float,
    runner: Runner | None,
) -> str:
    """Run ``rizin -q -c <script> <file>`` once, bounded; return stdout.

    With the default runner the typed rizin-missing failure fires before
    anything is spawned; an injected ``runner`` stands in for
    ``subprocess.run`` entirely, so the PATH probe is skipped and the pipeline
    runs offline against canned output.
    """
    if runner is None:
        _require_rizin()
    checked = _check_timeout(timeout)
    command = ("rizin", "-q", "-c", script, str(target))
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"rizin -c {script!r} exceeded its timeout of {checked} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{RIZIN_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
            "executable vanished between the PATH probe and the call"
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
            f"rizin -c {script!r} exited with code {returncode}: "
            f"{_tail(stderr_text) or 'no stderr output'}"
        )
    return stdout if isinstance(stdout, str) else ""


# --- dataclasses ---


@dataclass(frozen=True)
class RizinFunction:
    """One row of ``afl`` output: address, size and demangled-ish name."""

    address: int
    size: int | None
    name: str

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"address": f"0x{self.address:x}"}
        if self.size is not None:
            data["size"] = self.size
        data["name"] = self.name
        return data


@dataclass(frozen=True)
class RizinFunctionsResult:
    """Bounded function list from one ``rizin -q -c 'aaa; afl'`` run."""

    functions: tuple[RizinFunction, ...]
    truncated: bool
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="rizin -q -c 'aaa; afl'",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "functions": [function.to_dict() for function in self.functions],
            "count": len(self.functions),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class RizinInfoResult:
    """Key/value identity report from one ``rizin -q -c iI`` run."""

    fields: dict[str, str]
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="rizin -q -c iI",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": dict(self.fields),
            "count": len(self.fields),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_afl(text: str) -> RizinFunctionsResult:
    """Parse one ``afl`` transcript into a bounded, typed function list.

    Rows are whitespace-separated columns whose first token is the ``0x``
    address and whose last token is the function name; the size is the third
    column when it is numeric (rizin prints ``addr nbbs size ... name``).
    Junk rows and banners become warnings.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    warnings: list[str] = []
    functions: list[RizinFunction] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        tokens = stripped.split()
        if not _ADDRESS_TOKEN.match(tokens[0]):
            _note(warnings, f"skipping unrecognised afl row: {stripped[:80]}")
            continue
        name = tokens[-1]
        size: int | None = None
        if len(tokens) >= 3 and tokens[2].isdigit():
            size = int(tokens[2])
        functions.append(RizinFunction(address=int(tokens[0], 16), size=size, name=name))
    truncated = len(functions) > MAX_FUNCTIONS
    if truncated:
        _note(warnings, f"more than {MAX_FUNCTIONS} functions; kept the first {MAX_FUNCTIONS}")
    return RizinFunctionsResult(
        functions=tuple(functions[:MAX_FUNCTIONS]),
        truncated=truncated,
        warnings=warnings,
    )


def parse_ii(text: str) -> RizinInfoResult:
    """Parse one ``iI`` transcript into a bounded key/value report.

    Rows are ``key`` whitespace ``value``; the first occurrence of a key wins
    (duplicates become warnings), junk rows are skipped with a warning.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    warnings: list[str] = []
    fields: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _INFO_LINE.match(stripped)
        if match is None:
            _note(warnings, f"skipping unrecognised iI row: {stripped[:80]}")
            continue
        key = match.group("key")
        if key in fields:
            _note(warnings, f"ignoring duplicate iI key: {key}")
            continue
        if len(fields) >= MAX_INFO_FIELDS:
            _note(warnings, f"more than {MAX_INFO_FIELDS} fields; kept the first {MAX_INFO_FIELDS}")
            continue
        fields[key] = match.group("value")
    return RizinInfoResult(fields=fields, warnings=warnings)


def functions_of(
    path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> RizinFunctionsResult:
    """Run ``rizin -q -c 'aaa; afl'`` on ``path`` and parse the function list."""
    target = _check_path(path)
    out = _run_rizin("aaa; afl", target, timeout=timeout, runner=runner)
    return parse_afl(out)


def info_of(
    path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> RizinInfoResult:
    """Run ``rizin -q -c iI`` on ``path`` and parse the identity report."""
    target = _check_path(path)
    out = _run_rizin("iI", target, timeout=timeout, runner=runner)
    return parse_ii(out)




# --- live wrappers ---

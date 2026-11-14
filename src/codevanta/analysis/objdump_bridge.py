"""objdump disassembly bridge: text parser plus one skip-gated runner.

The adb/sigrok pattern applied to native disassembly: everything that
*understands* ``objdump -d`` output is the pure :func:`parse_objdump_text`
function, fully tested offline against canned AT&T and Intel transcripts, and
everything that *runs* objdump is :func:`objdump_disasm`, gated on a single
``shutil.which("objdump")`` probe with a bounded timeout and output capped at
:data:`MAX_LINES` lines before parsing. On a machine without objdump the
parser still runs and the wrapper still imports; it fails with the typed
:class:`~codevanta.core.report.AnalysisError` carrying the binutils install
hint -- never a traceback, never a partial decode.
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
    "MAX_LINES",
    "MAX_TIMEOUT",
    "OBJDUMP_MISSING_MESSAGE",
    "ObjdumpDisasmResult",
    "ObjdumpRow",
    "objdump_available",
    "objdump_disasm",
    "parse_objdump_text",
]

#: Default wall-clock budget for one objdump invocation, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one objdump invocation.
MAX_TIMEOUT = 120.0

#: Output lines kept from one invocation (the bounded-work cap).
MAX_LINES = 512

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "bridge.objdump"

#: Typed failure for the wrapper when objdump is absent, with install hint.
OBJDUMP_MISSING_MESSAGE = (
    "objdump is not on PATH; install GNU binutils "
    "(https://ftp.gnu.org/gnu/binutils/ or a platform package) and make sure "
    "it is on PATH"
)

#: ``  401000:	55                   	push   %rbp`` -- one instruction row in
#: either AT&T (``push %rbp``) or Intel (``push rbp``) syntax.
_OBJDUMP_ROW = re.compile(
    r"^\s*(?P<address>[0-9a-fA-F]+):\s+(?P<raw>[0-9a-fA-F][0-9a-fA-F ]*?)\s{2,}"
    r"(?P<mnemonic>\S+)(?:\s+(?P<operands>\S.*))?$"
)

#: ``i386:x86-64`` / ``arm`` -- one legal ``-m`` architecture name.
_ARCH_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$")


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
class ObjdumpRow:
    """One disassembled instruction row from an ``objdump -d`` transcript.

    Attributes:
        address: Instruction address (parsed from the hex column).
        bytes: Raw opcode bytes as printed, whitespace-normalised.
        mnemonic: The opcode mnemonic (AT&T and Intel share it).
        operands: The operand text as printed, ``None`` for no-operand rows.
    """

    address: int
    bytes: str
    mnemonic: str
    operands: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "address": self.address,
            "bytes": self.bytes,
            "mnemonic": self.mnemonic,
        }
        if self.operands is not None:
            data["operands"] = self.operands
        return data
@dataclass(frozen=True)
class ObjdumpDisasmResult:
    """Bounded, evidence-backed parse of one ``objdump -d`` transcript."""

    path: str
    arch: str | None = None
    rows: tuple[ObjdumpRow, ...] = ()
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="objdump -d",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "arch": self.arch,
            "instructions": [row.to_dict() for row in self.rows],
            "instruction_count": len(self.rows),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_objdump_text(text: Any, *, limit: int = MAX_LINES) -> ObjdumpDisasmResult:
    """Parse ``objdump -d`` output into bounded typed instruction rows.

    Handles both AT&T (``push %rbp``) and Intel (``push rbp``) column
    layouts; section headers (``Disassembly of section .text:``), symbol
    lines (``<main>:``) and file banners are skipped silently, and anything
    else unrecognised becomes a warning. Rows are bounded at ``limit``
    (default :data:`MAX_LINES`) with ``truncated`` reporting the drop. The
    parse never raises for transcript content; anything that is not ``str``
    raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    rows: list[ObjdumpRow] = []
    warnings: list[str] = []
    truncated = False
    for line in text.splitlines()[:limit]:
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        if (
            stripped.startswith("Disassembly of section")
            or "file format" in stripped
            or stripped.strip().endswith(">:")  # symbol heading like <main>:
            or ":" not in stripped
        ):
            continue  # file banner, section header, symbol line
        row = _OBJDUMP_ROW.match(stripped)
        if row is None:
            _note(warnings, f"unrecognised line skipped: {stripped.strip()[:64]!r}")
            continue
        operands = row.group("operands")
        rows.append(
            ObjdumpRow(
                address=int(row.group("address"), 16),
                bytes=" ".join(row.group("raw").split()),
                mnemonic=row.group("mnemonic"),
                operands=" ".join(operands.split()) if operands else None,
            )
        )
        if len(rows) >= limit:
            truncated = True
            _note(warnings, f"row limit {limit} reached; further instructions dropped")
            break
    if not rows and not warnings:
        _note(warnings, "no instruction rows in the transcript")
    return ObjdumpDisasmResult(
        path="",
        rows=tuple(rows),
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="objdump -d",
            confidence=Confidence.HIGH,
            detail=f"{len(rows)} instruction row(s)",
        ),
    )

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


def objdump_available() -> bool:
    """Report whether objdump is on ``PATH``; the only gate a caller needs."""
    return shutil.which("objdump") is not None


def objdump_disasm(
    input_path: str | Path,
    *,
    arch: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> ObjdumpDisasmResult:
    """Run ``objdump -d`` (optionally ``-m <arch>``) and parse the transcript.

    Skip-gated: without objdump on ``PATH`` (and no injected ``runner``) this
    raises the typed :data:`OBJDUMP_MISSING_MESSAGE` error before any process
    is spawned. Raw output is capped at :data:`MAX_LINES` lines before
    parsing, so one huge binary cannot exhaust the budget; ``truncated``
    reports both that cap and the parser's own bound.
    """
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"binary file not found: {target}")
    if arch is not None and (not isinstance(arch, str) or not _ARCH_RE.match(arch.strip())):
        raise AnalysisError(
            f"arch {arch!r} is not an objdump architecture name; expected letters, "
            "digits and . _ : + - only (e.g. i386:x86-64)"
        )
    checked_arch = arch.strip() if isinstance(arch, str) else None
    checked_timeout = _check_timeout(timeout)
    if runner is None and not objdump_available():
        raise AnalysisError(OBJDUMP_MISSING_MESSAGE)
    command: list[str] = ["objdump", "-d"]
    if checked_arch is not None:
        command.extend(["-m", checked_arch])
    command.append(str(target))
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(
            tuple(command), capture_output=True, text=True, timeout=checked_timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"objdump exceeded its timeout of {checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{OBJDUMP_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
            "executable vanished between the PATH probe and the call"
        ) from exc
    returncode = getattr(outcome, "returncode", None)
    if not isinstance(returncode, int):
        raise AnalysisError(
            "the runner outcome violates the injection contract: returncode must be an int"
        )
    stdout = getattr(outcome, "stdout", None)
    stderr_text = getattr(outcome, "stderr", "")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    transcript_text = stdout if isinstance(stdout, str) else ""
    if returncode != 0:
        raise AnalysisError(
            f"objdump exited with code {returncode}: "
            f"{_tail(str(stderr_text)) or 'no stderr output'}"
        )
    lines = transcript_text.splitlines()
    capped = "\n".join(lines[:MAX_LINES])
    parsed = parse_objdump_text(capped)
    truncated = parsed.truncated or len(lines) > MAX_LINES
    warnings = list(parsed.warnings)
    if len(lines) > MAX_LINES:
        _note(warnings, f"output capped at {MAX_LINES} lines; further lines dropped")
    return ObjdumpDisasmResult(
        path=str(target),
        arch=checked_arch,
        rows=parsed.rows,
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="objdump -d",
            confidence=Confidence.HIGH,
            detail=f"{len(parsed.rows)} instruction row(s)"
            + (f", arch {checked_arch}" if checked_arch else ""),
        ),
    )


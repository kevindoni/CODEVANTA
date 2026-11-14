"""Batch LLDB runner: one ``lldb -b`` invocation, one typed result.

The gdb lane's batch philosophy applied to LLDB: :func:`run_under_lldb` builds
a ``lldb --batch`` command line from ``-o`` one-shot commands (``target
create``, an optional ``breakpoint set``, ``run``, ``register read``, ``bt``,
caller ``commands``, ``quit``), runs it once under a wall-clock budget with an
injectable :class:`Runner`, and hands the transcript to the pure
:func:`parse_lldb_transcript` parser. The parser is fully tested offline
against canned transcripts byte for byte as lldb prints them: the ``stop
reason`` becomes :attr:`LldbRunResult.stopped_reason`, ``register read`` rows
become the ``registers`` dict (max :data:`MAX_REGISTERS`), ``bt`` rows become
frames (max :data:`MAX_FRAMES`), and the raw transcript is kept as a bounded
tail (max :data:`MAX_TAIL_LINES` lines).

Skip-gated like the adb/sigrok lanes: without ``lldb`` on ``PATH`` (and no
injected runner) the wrapper raises the typed
:data:`LLDB_MISSING_MESSAGE` error naming the install hint -- never a
traceback, never a partial result.
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
    "LLDB_MISSING_MESSAGE",
    "MAX_COMMANDS",
    "MAX_FRAMES",
    "MAX_REGISTERS",
    "MAX_TAIL_LINES",
    "MAX_TIMEOUT",
    "MAX_WARNINGS",
    "LldbFrame",
    "LldbRunResult",
    "Runner",
    "RunnerOutcome",
    "lldb_available",
    "parse_lldb_transcript",
    "run_under_lldb",
]

#: Evidence ``source`` id for this lane (``live.lldb``).
EVIDENCE_SOURCE = "live.lldb"

#: Default wall-clock budget for one ``lldb -b`` batch, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one ``lldb -b`` batch.
MAX_TIMEOUT = 120.0

#: Frames kept from the backtrace (bounded work).
MAX_FRAMES = 32

#: Registers kept from ``register read`` output (bounded work).
MAX_REGISTERS = 64

#: Raw transcript lines kept as the tail (bounded work).
MAX_TAIL_LINES = 200

#: Extra caller ``-o`` commands accepted per batch (bounded work).
MAX_COMMANDS = 32

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Typed failure for the wrapper when lldb is absent, with the install hint.
LLDB_MISSING_MESSAGE = (
    "lldb is not on PATH; install the LLVM toolchain "
    "(https://releases.llvm.org) and make sure lldb is on PATH"
)

#: ``* frame #0: 0x0000000000401000 a.out`main`` -- one ``bt`` row.
_FRAME_LINE = re.compile(
    r"^\s*(?P<current>\*\s*)?frame\s+#(?P<index>\d+):\s+"
    r"(?P<addr>0x[0-9a-fA-F]+)\s+(?P<rest>\S.*)$"
)

#: ``rax = 0x0000000000000001`` (and friends) -- one ``register read`` row;
#: tolerant of several ``name = value`` pairs sharing one line.
_REGISTER_PAIR = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9]{0,31})\s*=\s*(?P<value>0x[0-9a-fA-F]+|\d+)"
)

#: ``stop reason = breakpoint 1.1`` -- the batch stop report.
_STOP_REASON = re.compile(r"stop reason\s*=\s*(?P<reason>[^\r\n]+)")

#: ``Process 1234 exited with status = 0`` -- the batch exit report.
_EXIT_STATUS = re.compile(r"exited with status\s*=\s*(?P<status>-?\d+)")

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


def _check_timeout(timeout_s: Any) -> float:
    """Validate the wall-clock budget of one batch."""
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        raise AnalysisError(f"timeout_s must be a positive number of seconds, got {timeout_s!r}")
    if not 1.0 <= float(timeout_s) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout_s {timeout_s} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(timeout_s)


def _check_commands(commands: Any) -> tuple[str, ...]:
    """Validate the extra ``-o`` commands (count, emptiness, length)."""
    if commands is None:
        return ()
    if isinstance(commands, str) or not hasattr(commands, "__iter__"):
        raise AnalysisError(
            f"commands must be a sequence of strings, got {type(commands).__name__}"
        )
    collected: list[str] = []
    for command in commands:
        if not isinstance(command, str):
            raise AnalysisError(
                f"commands must be strings, got one {type(command).__name__} entry"
            )
        stripped = command.strip()
        if not stripped:
            raise AnalysisError("commands must not contain empty strings")
        if len(stripped) > 256:
            raise AnalysisError(
                f"command is {len(stripped)} characters long; expected at most 256"
            )
        collected.append(stripped)
        if len(collected) > MAX_COMMANDS:
            raise AnalysisError(
                f"more than {MAX_COMMANDS} commands; expected at most {MAX_COMMANDS}"
            )
    return tuple(collected)


def _break_spec(break_at: str) -> tuple[str, str]:
    """Classify ``--break`` into ``("address", "0x..")`` or ``("name", X)``.

    ``0x401000`` and all-digit text are addresses; anything else is a symbol
    name handed to ``breakpoint set --name`` verbatim.
    """
    if not isinstance(break_at, str):
        raise AnalysisError(f"break_at must be a string, got {type(break_at).__name__}")
    text = break_at.strip()
    if not text:
        raise AnalysisError("break_at must be a function name or an address, not empty")
    lowered = text.lower()
    if lowered.startswith("0x") or text.isdigit():
        try:
            value = int(text, 16 if lowered.startswith("0x") else 10)
        except ValueError as exc:
            raise AnalysisError(
                f"break_at {break_at!r} looks like an address but does not parse"
            ) from exc
        if value <= 0:
            raise AnalysisError(f"break_at address must be positive, got {value}")
        return "address", f"0x{value:x}"
    return "name", text


def _lldb_path() -> str | None:
    """Probe ``PATH`` for lldb; nothing else can fail."""
    return shutil.which("lldb")


def lldb_available() -> bool:
    """Report whether lldb is on ``PATH``; the only gate a caller needs."""
    return _lldb_path() is not None


def _require_lldb() -> None:
    """Raise the typed skip-gate failure when lldb is absent."""
    if _lldb_path() is None:
        raise AnalysisError(LLDB_MISSING_MESSAGE)


# --- dataclasses ---


@dataclass(frozen=True)
class LldbFrame:
    """One row of the ``bt`` backtrace (address kept as printed hex text)."""

    index: int
    address: str
    module: str | None = None
    symbol: str | None = None
    current: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "index": self.index,
            "address": self.address,
            "module": self.module,
            "symbol": self.symbol,
        }
        if self.current:
            data["current"] = True
        return data


@dataclass(frozen=True)
class LldbRunResult:
    """Typed result of one bounded ``lldb -b`` batch run."""

    stopped_reason: str | None
    registers: dict[str, str]
    frames: tuple[LldbFrame, ...]
    raw_tail: tuple[str, ...]
    truncated_frames: bool
    command: tuple[str, ...]
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="lldb -b batch",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "stopped_reason": self.stopped_reason,
            "registers": dict(self.registers),
            "frames": [frame.to_dict() for frame in self.frames],
            "frame_count": len(self.frames),
            "truncated_frames": self.truncated_frames,
            "raw_tail": list(self.raw_tail),
            "command": list(self.command),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_lldb_transcript(text: str) -> LldbRunResult:
    """Parse one ``lldb -b`` transcript into the typed, bounded result.

    ``stop reason = ...`` becomes ``stopped_reason`` (``exited with status = N``
    is recognised as its own reason); ``register read`` rows become the
    ``registers`` dict capped at :data:`MAX_REGISTERS`; ``bt`` rows become
    frames capped at :data:`MAX_FRAMES`; the raw transcript is kept as a tail
    capped at :data:`MAX_TAIL_LINES` lines. Junk is tolerated as warnings.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    warnings: list[str] = []
    stopped_reason: str | None = None
    registers: dict[str, str] = {}
    frames: list[LldbFrame] = []
    seen_keys: set[tuple[int, str, str | None, str | None]] = set()
    frames_seen_at: dict[tuple[int, str, str | None, str | None], int] = {}
    for match in _STOP_REASON.finditer(text):
        stopped_reason = match.group("reason").strip()
        break
    if stopped_reason is None:
        exit_match = _EXIT_STATUS.search(text)
        if exit_match is not None:
            stopped_reason = f"exited with status = {exit_match.group('status')}"
    for match in _REGISTER_PAIR.finditer(text):
        if len(registers) >= MAX_REGISTERS:
            _note(warnings, f"more than {MAX_REGISTERS} registers; kept the first {MAX_REGISTERS}")
            break
        registers.setdefault(match.group("name").lower(), match.group("value"))
    for line in text.splitlines():
        frame_match = _FRAME_LINE.match(line)
        if frame_match is None:
            continue
        if len(frames) >= MAX_FRAMES:
            _note(warnings, f"more than {MAX_FRAMES} frames; kept the first {MAX_FRAMES}")
            break
        module, symbol = _split_frame_rest(frame_match.group("rest"))
        key = (int(frame_match.group("index")), frame_match.group("addr"), module, symbol)
        current = frame_match.group("current") is not None
        if key in seen_keys:
            if current and frames_seen_at.get(key) is not None:
                # the stop report and `bt` often print the same frame; keep the
                # ``*`` current marker if any rendering of the row carried it
                idx = frames_seen_at[key]
                frames[idx] = (
                    LldbFrame(
                        index=frames[idx].index,
                        address=frames[idx].address,
                        module=frames[idx].module,
                        symbol=frames[idx].symbol,
                        current=True,
                    )
                )
            continue
        seen_keys.add(key)
        frames_seen_at[key] = len(frames)
        frames.append(
            LldbFrame(
                index=key[0],
                address=key[1],
                module=module,
                symbol=symbol,
                current=current,
            )
        )
    lines = text.splitlines()
    raw_tail = tuple(lines[-MAX_TAIL_LINES:])
    if stopped_reason is None:
        _note(warnings, "no stop reason or exit status found in the transcript")
    return LldbRunResult(
        stopped_reason=stopped_reason,
        registers=registers,
        frames=tuple(frames),
        raw_tail=raw_tail,
        truncated_frames=len(frames) >= MAX_FRAMES,
        command=(),
        warnings=warnings,
    )


def _split_frame_rest(rest: str) -> tuple[str | None, str | None]:
    """Split a ``bt`` row's ``module`symbol + off`` rest into module/symbol."""
    if "`" in rest:
        module, _, symbol_text = rest.partition("`")
        symbol = symbol_text.split(" + ")[0].strip() or None
        return module.strip() or None, symbol
    return None, rest.strip() or None
class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped."""

    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> RunnerOutcome: ...


def run_under_lldb(
    target: str | Path,
    break_at: str | None = None,
    commands: list[str] | tuple[str, ...] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT,
    *,
    runner: Runner | None = None,
) -> LldbRunResult:
    """Run ``target`` under one bounded ``lldb -b`` batch and parse the result.

    The batch is: ``target create``, an optional ``breakpoint set`` (symbol
    name or ``0x`` address), ``run``, ``register read``, ``bt``, the caller's
    ``commands`` and ``quit``. Skip-gated: without lldb on ``PATH`` (and no
    injected ``runner``) the typed :data:`LLDB_MISSING_MESSAGE` error fires
    before any process is spawned.

    Raises:
        AnalysisError: lldb missing, target file missing, bad budget, bad
            ``commands``, a batch that missed its wall-clock budget, or a
            failed batch whose transcript carries no stop report.
    """
    if not isinstance(target, (str, Path)):
        raise AnalysisError(f"target must be a str or Path, got {type(target).__name__}")
    target_path = Path(target)
    if not target_path.is_file():
        raise AnalysisError(f"target binary not found: {target_path}")
    checked_timeout = _check_timeout(timeout_s)
    extra = _check_commands(commands)
    checked_break: tuple[str, str] | None = None
    if break_at is not None:
        checked_break = _break_spec(break_at)
    if runner is None:
        _require_lldb()
    argv: list[str] = ["lldb", "-b", "-o", f'target create "{target_path}"']
    if checked_break is not None:
        kind, spec = checked_break
        argv.extend(("-o", f"breakpoint set --{kind} {spec}"))
    argv.extend(("-o", "run"))
    argv.extend(("-o", "register read"))
    argv.extend(("-o", "bt"))
    for command in extra:
        argv.extend(("-o", command))
    argv.extend(("-o", "quit"))
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(tuple(argv), capture_output=True, text=True, timeout=checked_timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"lldb -b exceeded its timeout of {checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{LLDB_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
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
    result = parse_lldb_transcript(stdout if isinstance(stdout, str) else "")
    warnings = list(result.warnings)
    if returncode != 0:
        if result.stopped_reason is None:
            raise AnalysisError(
                f"lldb -b exited with code {returncode} without a stop report: "
                f"{_tail(stderr_text) or _tail(stdout if isinstance(stdout, str) else '')}"
            )
        _note(warnings, f"lldb -b exited with code {returncode}")
    return LldbRunResult(
        stopped_reason=result.stopped_reason,
        registers=result.registers,
        frames=result.frames,
        raw_tail=result.raw_tail,
        truncated_frames=result.truncated_frames,
        command=tuple(argv),
        warnings=warnings,
    )




# --- live wrapper ---

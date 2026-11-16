"""Owned process capture and capture-to-capture comparison (bounded, honest).

:func:`capture_process` executes *the caller-selected command* on this machine
as an owned child process -- ``subprocess.run`` in argv form, no shell, no PTY.
It exists for the same reason the REA lane's capture scenario exists: some
questions (``does this stub unpack itself``, ``what does the installer print``)
can only be answered by running the thing. Honesty rules:

* the command executes **locally** -- this is dynamic evidence, not static
  analysis, and every MCP tool built on this module says so in its description;
* output is captured **via pipes** -- there is no terminal emulation and no
  pseudo-terminal, so tty-sensitive behaviour (color, prompts) is not modelled;
* everything is **bounded**: at most :data:`MAX_OUTPUT_BYTES` (1 MiB) of raw
  bytes per stream is kept (the sha256 always covers the *full* raw bytes, so a
  truncated capture is still verifiable), the wall-clock budget is at most
  :data:`MAX_TIMEOUT` seconds, argv may carry at most :data:`MAX_ARGS`
  arguments and ``env`` at most :data:`MAX_ENV_ENTRIES` extra variables
  (merged on top of the inherited environment -- replacing it entirely breaks
  child processes on Windows);
* a timeout is an **honest state**, not a crash: the partial output gathered so
  far is kept, ``exit_code`` is ``None`` and a warning says the process was
  terminated.

Everything that *understands* a capture is pure and offline-testable:
``runner`` stands in for ``subprocess.run`` entirely (the same injection
contract as :mod:`codevanta.analysis.frida_bridge`), so canned outcomes drive
the whole pipeline in tests. The only exception raised is
:class:`~codevanta.core.report.AnalysisError`, and only for a caller mistake or
a runner that violates the injection contract. :func:`compare_captures` is
deterministic on the stored bytes: digests decide identity, and the text diff
is :func:`difflib.unified_diff` capped at :data:`MAX_DIFF_LINES` lines. The
session registry that hands out ``proc-001``-style ids lives in the MCP ext
layer (:mod:`codevanta.mcp_server.ext_proccapture`), not here.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_TIMEOUT",
    "EVIDENCE_SOURCE",
    "EVIDENCE_SOURCE_COMPARE",
    "MAX_ARGS",
    "MAX_DIFF_LINES",
    "MAX_ENV_ENTRIES",
    "MAX_OUTPUT_BYTES",
    "MAX_TIMEOUT",
    "MAX_WARNINGS",
    "VERDICT_DIVERGENT",
    "VERDICT_EXIT_MISMATCH",
    "VERDICT_IDENTICAL",
    "VERDICT_OUTPUT_MISMATCH",
    "ProcCapture",
    "ProcCompare",
    "ProcOutcome",
    "ProcRunner",
    "capture_process",
    "compare_captures",
]

#: Evidence ``source`` id for a single capture (``proc.capture``).
EVIDENCE_SOURCE = "proc.capture"

#: Evidence ``source`` id for a capture-to-capture comparison.
EVIDENCE_SOURCE_COMPARE = "proc.compare"

#: Default wall-clock budget for one capture, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one capture (seconds).
MAX_TIMEOUT = 120.0

#: Hard ceiling on the number of argv arguments accepted.
MAX_ARGS = 32

#: Hard ceiling on the number of extra environment variables accepted.
MAX_ENV_ENTRIES = 16

#: Hard ceiling on raw bytes kept per output stream (1 MiB). The sha256 always
#: covers the full raw bytes, so a truncated capture stays verifiable.
MAX_OUTPUT_BYTES = 1024 * 1024

#: Lines kept per ``unified_diff`` stream before the rest is summarised away.
MAX_DIFF_LINES = 200

#: Ceiling on warnings kept per capture.
MAX_WARNINGS = 32

#: Verdicts :func:`compare_captures` can produce.
VERDICT_IDENTICAL = "identical"
VERDICT_EXIT_MISMATCH = "exit-mismatch"
VERDICT_OUTPUT_MISMATCH = "output-mismatch"
VERDICT_DIVERGENT = "divergent"


class ProcOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped."""

    returncode: int
    stdout: Any
    stderr: Any


class ProcRunner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: list[str], **kwargs: Any) -> ProcOutcome: ...


def _warn(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; summarised...")


def _check_command(command: Any) -> str:
    """Validate the command: one non-empty string, run without a shell."""
    if not isinstance(command, str) or not command.strip():
        raise AnalysisError(f"command must be a non-empty string, got {command!r}")
    return command.strip()


def _check_arguments(arguments: Any) -> tuple[str, ...]:
    """Validate the argument list: at most :data:`MAX_ARGS` scalar items."""
    if arguments is None:
        return ()
    if isinstance(arguments, (str, bytes)) or not isinstance(arguments, Sequence):
        raise AnalysisError(
            f"arguments must be a list of strings, got {type(arguments).__name__}"
        )
    checked: list[str] = []
    for item in arguments:
        if isinstance(item, bool) or not isinstance(item, (str, int, float)):
            raise AnalysisError(
                f"arguments must be strings (or plain numbers), got {item!r}"
            )
        checked.append(str(item))
    if len(checked) > MAX_ARGS:
        raise AnalysisError(
            f"too many arguments: {len(checked)} given, at most {MAX_ARGS} accepted"
        )
    return tuple(checked)


def _check_timeout(timeout: Any) -> float:
    """Validate the wall-clock budget against :data:`MAX_TIMEOUT`."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AnalysisError(f"timeout must be a positive number of seconds, got {timeout!r}")
    if not 1.0 <= float(timeout) <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return float(timeout)


def _check_working_directory(working_directory: Any) -> str | None:
    """Validate the working directory: ``None`` inherits, else it must exist."""
    if working_directory is None:
        return None
    if not isinstance(working_directory, str) or not working_directory.strip():
        raise AnalysisError(
            f"working_directory must be a directory path or None, got {working_directory!r}"
        )
    expanded = os.path.expanduser(working_directory.strip())
    if not os.path.isdir(expanded):
        raise AnalysisError(f"working_directory is not a directory: {expanded}")
    return expanded


def _check_env(env: Any) -> dict[str, str] | None:
    """Validate extra environment variables against :data:`MAX_ENV_ENTRIES`.

    The entries are merged **on top of** the inherited environment (replacing
    it wholesale would strip ``SystemRoot`` and friends, which child processes
    on Windows need), so a key that is already set is overridden, nothing else.
    """
    if env is None:
        return None
    if not isinstance(env, Mapping):
        raise AnalysisError(f"env must be a mapping of name to value, got {type(env).__name__}")
    if len(env) > MAX_ENV_ENTRIES:
        raise AnalysisError(
            f"too many env entries: {len(env)} given, at most {MAX_ENV_ENTRIES} accepted"
        )
    checked: dict[str, str] = {}
    for key, value in env.items():
        if isinstance(key, bool) or not isinstance(key, (str, int, float)):
            raise AnalysisError(f"env keys must be strings, got {key!r}")
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise AnalysisError(f"env values must be strings, got {value!r}")
        checked[str(key)] = str(value)
    return checked


def _check_max_output_bytes(max_output_bytes: Any) -> int:
    """Validate the per-stream byte bound against :data:`MAX_OUTPUT_BYTES`."""
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int):
        raise AnalysisError(
            f"max_output_bytes must be an integer, got {type(max_output_bytes).__name__}"
        )
    if not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise AnalysisError(
            f"max_output_bytes {max_output_bytes} is out of range; "
            f"expected 1 .. {MAX_OUTPUT_BYTES}"
        )
    return int(max_output_bytes)


def _as_bytes(raw: Any, stream: str) -> bytes:
    """Normalise one runner outcome field to raw bytes.

    The contract prefers ``bytes`` (what ``subprocess.run`` yields without
    ``text=True``); a ``str`` outcome is accepted from text-mode doubles and
    encoded as UTF-8. Anything else violates the injection contract.
    """
    if raw is None:
        return b""
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8")
    raise AnalysisError(
        f"the runner outcome violates the injection contract: {stream} must be "
        f"bytes, str or None, got {type(raw).__name__}"
    )


def _bound(raw: bytes, limit: int) -> tuple[bytes, bool]:
    """Return ``(kept_bytes, truncated)`` for one stream's raw bytes."""
    if len(raw) <= limit:
        return raw, False
    return raw[:limit], True


@dataclass(frozen=True)
class ProcCapture:
    """Everything one bounded owned-subprocess run produced, honestly.

    Attributes:
        command: The exact ``argv`` that was executed (command + arguments).
        exit_code: The child's exit code, or ``None`` when the budget ended
            the run before the child exited on its own (``timed_out``).
        duration_ms: Wall-clock duration of the invocation, in milliseconds.
        stdout / stderr: The captured streams, decoded as UTF-8 with
            replacements, each cut at the caller's byte bound.
        stdout_truncated / stderr_truncated: ``True`` when that stream's raw
            bytes exceeded the bound and only the head is kept. The sha256
            digests still cover the *full* raw bytes either way.
        stdout_sha256 / stderr_sha256: Digest of the full raw stream bytes.
        stdout_bytes / stderr_bytes: Size of the full raw stream, in bytes.
        timed_out: ``True`` when the wall-clock budget ended the run; the
            partial output gathered so far is what the fields carry.
        started_at / finished_at: UTC timestamps (ISO 8601) around the run.
        working_directory: The directory the child ran in, when one was set.
        warnings: Bounds that bit, the timeout, decode oddities.
        evidence: How the capture was produced, including the budgets.
    """

    command: tuple[str, ...]
    exit_code: int | None
    duration_ms: float
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    started_at: str
    finished_at: str
    working_directory: str | None
    disposition: str = "exited"
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="owned-subprocess",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the capture for the MCP payload (JSON-safe values only)."""
        return {
            "command": list(self.command),
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "timed_out": self.timed_out,
            "disposition": self.disposition,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "working_directory": self.working_directory,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def capture_process(
    command: str,
    arguments: Sequence[str] = (),
    working_directory: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    *,
    runner: ProcRunner | None = None,
) -> ProcCapture:
    """Run the caller-selected command locally and capture it, bounded.

    The child is spawned through ``subprocess.run`` in argv form -- no shell,
    no PTY, output captured via pipes -- with a wall-clock budget at most
    :data:`MAX_TIMEOUT` seconds and at most ``max_output_bytes`` raw bytes kept
    per stream (sha256 over the full raw bytes regardless). An injected
    ``runner`` stands in for ``subprocess.run`` entirely, which is what the
    offline tests drive; with the default runner a missing executable and a
    contract-violating outcome become typed errors.

    Args:
        command: Executable to run, without a shell.
        arguments: At most :data:`MAX_ARGS` scalar argv items.
        working_directory: Directory to run in, or ``None`` to inherit.
        timeout: Wall-clock budget, ``1 ..`` :data:`MAX_TIMEOUT` seconds. On
            expiry the child is terminated and the run is reported honestly
            (``timed_out``, ``exit_code=None``, partial output kept).
        env: At most :data:`MAX_ENV_ENTRIES` extra variables, merged on top of
            the inherited environment.
        max_output_bytes: Per-stream bound, ``1 ..`` :data:`MAX_OUTPUT_BYTES`.
        runner: Injectable ``subprocess.run`` stand-in (tests/embedding).

    Returns:
        A frozen :class:`ProcCapture` with evidence ``proc.capture`` /
        ``owned-subprocess`` at HIGH confidence (these are raw observed facts).

    Raises:
        AnalysisError: Any input is out of bounds, the executable is missing,
            or the runner breaks its injection contract.
    """
    argv = (_check_command(command), *_check_arguments(arguments))
    checked_timeout = _check_timeout(timeout)
    checked_cwd = _check_working_directory(working_directory)
    checked_env = _check_env(env)
    checked_bound = _check_max_output_bytes(max_output_bytes)

    kwargs: dict[str, Any] = {"capture_output": True, "timeout": checked_timeout}
    if checked_cwd is not None:
        kwargs["cwd"] = checked_cwd
    if checked_env is not None:
        kwargs["env"] = {**os.environ, **checked_env}

    execute = runner if runner is not None else subprocess.run
    warnings: list[str] = []
    timed_out = False
    exit_code: int | None = None
    started = datetime.now(timezone.utc)
    clock = time.monotonic()
    try:
        outcome = execute(list(argv), **kwargs)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        raw_stdout = _as_bytes(exc.stdout, "stdout")
        raw_stderr = _as_bytes(exc.stderr, "stderr")
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"command not found: {command!r} (it would have run locally as an "
            "owned subprocess)"
        ) from exc
    else:
        observed = getattr(outcome, "returncode", None)
        if not isinstance(observed, int):
            raise AnalysisError(
                "the runner outcome violates the injection contract: returncode "
                "must be an int"
            )
        exit_code = observed
        raw_stdout = _as_bytes(getattr(outcome, "stdout", None), "stdout")
        raw_stderr = _as_bytes(getattr(outcome, "stderr", None), "stderr")
    elapsed_ms = (time.monotonic() - clock) * 1000.0
    finished = datetime.now(timezone.utc)

    kept_stdout, stdout_truncated = _bound(raw_stdout, checked_bound)
    kept_stderr, stderr_truncated = _bound(raw_stderr, checked_bound)
    if stdout_truncated:
        _warn(
            warnings,
            f"stdout had {len(raw_stdout)} raw bytes; kept the first "
            f"{checked_bound} (digest covers all of them)",
        )
    if stderr_truncated:
        _warn(
            warnings,
            f"stderr had {len(raw_stderr)} raw bytes; kept the first "
            f"{checked_bound} (digest covers all of them)",
        )
    if timed_out:
        _warn(
            warnings,
            f"the command exceeded its timeout of {checked_timeout:g} seconds and "
            "was terminated; exit code unknown, partial output kept",
        )
        _warn(
            warnings,
            "the timeout terminated the child itself; processes the child spawned "
            "are outside this capture and were not tracked or cleaned up",
        )
    disposition = "terminated-after-timeout" if timed_out else "exited"

    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="owned-subprocess",
        confidence=Confidence.HIGH,
        detail=(
            f"ran argv[0]={argv[0]!r} with {len(argv) - 1} argument(s) locally; "
            "output captured via pipes, no terminal emulation"
        ),
        extra={
            "timeout": checked_timeout,
            "max_output_bytes": checked_bound,
            "timed_out": timed_out,
            "exit_code": exit_code,
            "stdout_bytes": len(raw_stdout),
            "stderr_bytes": len(raw_stderr),
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "warning_count": len(warnings),
        },
    )
    return ProcCapture(
        command=argv,
        exit_code=exit_code,
        duration_ms=round(elapsed_ms, 3),
        stdout=kept_stdout.decode("utf-8", "replace"),
        stderr=kept_stderr.decode("utf-8", "replace"),
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        stdout_sha256=hashlib.sha256(raw_stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(raw_stderr).hexdigest(),
        stdout_bytes=len(raw_stdout),
        stderr_bytes=len(raw_stderr),
        timed_out=timed_out,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        working_directory=checked_cwd,
        disposition=disposition,
        warnings=tuple(warnings),
        evidence=evidence,
    )


@dataclass(frozen=True)
class ProcCompare:
    """Deterministic comparison of two captures, computed on stored bytes.

    Attributes:
        verdict: ``identical`` (exit codes and both stream digests match),
            ``exit-mismatch`` (streams match, exit codes differ),
            ``output-mismatch`` (exit codes match, a stream differs) or
            ``divergent`` (both differ).
        exit_match: ``True`` when both exit codes are equal (``None == None``
            counts as equal: two budget-terminated runs).
        duration_delta_ms: ``abs(left.duration_ms - right.duration_ms)``.
        stdout_digest_match / stderr_digest_match: Digest equality per stream.
        stdout_diff / stderr_diff: ``difflib.unified_diff`` lines for a
            mismatched stream, capped at :data:`MAX_DIFF_LINES`; empty when
            the streams match.
        diff_truncated: ``True`` when at least one diff was cut at the cap.
        evidence: How the comparison was produced.
    """

    verdict: str
    exit_match: bool
    duration_delta_ms: float
    stdout_digest_match: bool
    stderr_digest_match: bool
    stdout_diff: tuple[str, ...]
    stderr_diff: tuple[str, ...]
    diff_truncated: bool
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE_COMPARE,
            method="unified-diff",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the comparison for the MCP payload."""
        return {
            "verdict": self.verdict,
            "exit_match": self.exit_match,
            "duration_delta_ms": self.duration_delta_ms,
            "stdout_digest_match": self.stdout_digest_match,
            "stderr_digest_match": self.stderr_digest_match,
            "stdout_diff": list(self.stdout_diff),
            "stderr_diff": list(self.stderr_diff),
            "diff_truncated": self.diff_truncated,
            "evidence": self.evidence.to_dict(),
        }


def _unified_diff(left: str, right: str, label: str) -> tuple[tuple[str, ...], bool]:
    """Diff one stream pair, capped at :data:`MAX_DIFF_LINES` lines."""
    lines = difflib.unified_diff(
        left.splitlines(),
        right.splitlines(),
        fromfile=f"left/{label}",
        tofile=f"right/{label}",
        lineterm="",
    )
    kept: list[str] = []
    truncated = False
    for line in lines:
        if len(kept) >= MAX_DIFF_LINES:
            truncated = True
            break
        kept.append(line)
    return tuple(kept), truncated


def compare_captures(left: ProcCapture, right: ProcCapture) -> ProcCompare:
    """Compare two captures deterministically on their stored bytes.

    Identity is decided by the exit codes and the full-stream sha256 digests;
    mismatched streams are diffed with :func:`difflib.unified_diff`, capped at
    :data:`MAX_DIFF_LINES` lines per stream. Nothing is re-run: the comparison
    reads exactly the two records it was given.

    Raises:
        AnalysisError: Either argument is not a :class:`ProcCapture`.
    """
    for name, record in (("left", left), ("right", right)):
        if not isinstance(record, ProcCapture):
            raise AnalysisError(
                f"{name} must be a ProcCapture, got {type(record).__name__}"
            )
    exit_match = left.exit_code == right.exit_code
    stdout_match = left.stdout_sha256 == right.stdout_sha256
    stderr_match = left.stderr_sha256 == right.stderr_sha256
    stdout_diff, stdout_cut = (
        _unified_diff(left.stdout, right.stdout, "stdout")
        if not stdout_match
        else ((), False)
    )
    stderr_diff, stderr_cut = (
        _unified_diff(left.stderr, right.stderr, "stderr")
        if not stderr_match
        else ((), False)
    )
    if exit_match and stdout_match and stderr_match:
        verdict = VERDICT_IDENTICAL
    elif stdout_match and stderr_match:
        verdict = VERDICT_EXIT_MISMATCH
    elif exit_match:
        verdict = VERDICT_OUTPUT_MISMATCH
    else:
        verdict = VERDICT_DIVERGENT
    evidence = Evidence(
        source=EVIDENCE_SOURCE_COMPARE,
        method="unified-diff",
        confidence=Confidence.HIGH,
        detail=f"{verdict}: computed on the stored bytes of both captures",
        extra={
            "verdict": verdict,
            "exit_match": exit_match,
            "stdout_digest_match": stdout_match,
            "stderr_digest_match": stderr_match,
            "diff_lines_kept": len(stdout_diff) + len(stderr_diff),
            "diff_truncated": stdout_cut or stderr_cut,
        },
    )
    return ProcCompare(
        verdict=verdict,
        exit_match=exit_match,
        duration_delta_ms=round(abs(left.duration_ms - right.duration_ms), 3),
        stdout_digest_match=stdout_match,
        stderr_digest_match=stderr_match,
        stdout_diff=stdout_diff,
        stderr_diff=stderr_diff,
        diff_truncated=stdout_cut or stderr_cut,
        evidence=evidence,
    )


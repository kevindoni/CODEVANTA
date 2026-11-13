"""Run a generated gdb session and return its parsed trace report.

:mod:`codevanta.analysis.dynamic` writes the session script and
:mod:`codevanta.analysis.trace` reads a saved log; this module is the narrow
bridge between them: it *actually runs* the generated script through gdb and
hands the captured stdout to :func:`codevanta.analysis.trace.parse_gdb_trace`.
On a machine without gdb -- a Windows workstation, a slim CI container --
nothing here could run against a real process, so the module is built to work
without one:

* :func:`gdb_available` probes ``PATH`` with ``shutil.which`` and nothing
  else. It never imports ``frida`` and never executes gdb, so the probe cannot
  fail.
* :func:`run_breakpoints` takes an injectable ``runner`` callable that stands
  in for ``subprocess.run``. A test (or an embedding host) can supply any
  callable with the same contract and drive the full
  build -> write -> run -> parse -> cleanup pipeline against canned output,
  byte for byte as gdb would have printed it.

The injection contract
----------------------
``runner`` is called as ``runner(command, **kwargs)``: ``command`` is the exact
``argv`` tuple (``("gdb", "-q", "-batch", "-x", <script>, "--args", <target>)``)
and ``kwargs`` carry ``capture_output=True``, ``text=True`` and
``timeout=<seconds>``. It must return an object exposing ``.returncode`` (an
``int``), ``.stdout`` and ``.stderr`` -- the ``subprocess.CompletedProcess``
that ``subprocess.run(..., capture_output=True, text=True)`` returns satisfies
this. ``runner=None`` (the default) means ``subprocess.run`` itself.

Every failure names what is missing or wrong
--------------------------------------------
A missing gdb executable, a session that exceeds ``timeout``, an empty or
non-``int`` address list, an out-of-range ``max_hits`` -- all raise
:class:`~codevanta.core.report.AnalysisError` naming the offending input, and
none of them leaves a script file behind. A non-zero gdb exit code is *not*
an error: the output is still parsed and the condition is reported as a
warning on the :class:`GdbRunResult` (the parser's own warnings live on
``report.warnings``). The script file is always removed once the run ends,
whether it succeeded, failed or raised; when ``script_dir`` is supplied, only
the file this module wrote is removed -- the directory itself and its other
contents are left alone.
"""


from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeAlias

from codevanta.analysis.dynamic import DEFAULT_MAX_HITS, build_gdb_script, script_file_name
from codevanta.analysis.trace import TraceReport, parse_gdb_trace
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError

__all__ = [
    "DEFAULT_TIMEOUT",
    "GdbRunResult",
    "Runner",
    "RunnerOutcome",
    "gdb_available",
    "run_breakpoints",
]

#: Default wall-clock budget for one gdb session, in seconds.
DEFAULT_TIMEOUT = 60.0


class RunnerOutcome(Protocol):
    """What a runner must return: ``subprocess.CompletedProcess``-shaped.

    Attributes:
        returncode: The gdb process exit code (``0`` on success).
        stdout: Everything gdb printed, decoded to text.
        stderr: Everything gdb wrote to its error stream, decoded to text.
    """

    returncode: int
    stdout: str
    stderr: str


#: A callable standing in for ``subprocess.run``; see :func:`run_breakpoints`.
Runner: TypeAlias = Callable[..., RunnerOutcome]


def _default_runner(command: Sequence[str], **kwargs: Any) -> RunnerOutcome:
    """Run ``command`` through :func:`subprocess.run`; the production runner."""
    return subprocess.run(command, **kwargs)


def gdb_available() -> bool:
    """Return ``True`` when the ``gdb`` executable can be found on ``PATH``.

    The probe is ``shutil.which("gdb")`` and nothing else: no provider package
    is imported (Frida in particular is never touched) and no process is
    started, so asking cannot fail and cannot have side effects.
    """
    return shutil.which("gdb") is not None


@dataclass(frozen=True)
class GdbRunResult:
    """Everything one gdb session produced, plus how it was run.

    Attributes:
        report: The parsed trace: hits, backtraces, function attribution and
            the parser's own warnings.
        exit_code: The exit code gdb itself returned. Non-zero is reported as
            a warning, not an error: the output was still parsed.
        script_path: Path of the session script that was executed. The file is
            removed before this result is returned, so the path is a record,
            not a handle.
        command: The exact ``argv`` tuple that was (or would have been)
            executed.
        raw_output_path: Path where the raw gdb output was persisted, or
            ``None``. The default run parses stdout in memory and persists
            nothing.
        warnings: Run-level warnings: a non-zero gdb exit code, a script file
            that could not be removed. Parse-level warnings are on
            ``report.warnings``.

    """

    report: TraceReport
    exit_code: int
    script_path: str
    command: tuple[str, ...]
    raw_output_path: str | None
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the run for the JSON report (JSON-safe values only)."""
        return {
            "report": self.report.to_dict(),
            "exit_code": self.exit_code,
            "script_path": self.script_path,
            "command": list(self.command),
            "raw_output_path": self.raw_output_path,
            "warnings": list(self.warnings),
        }


def _require_timeout(timeout: float) -> float:
    """Return ``timeout`` after checking it is a positive number of seconds."""
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        raise AnalysisError(
            f"timeout must be a number of seconds, got {type(timeout).__name__}: {timeout!r}"
        )
    if timeout <= 0:
        raise AnalysisError(f"timeout must be positive, got {timeout}")
    return float(timeout)


def _as_text(value: Any) -> str:
    """Return ``value`` as text, tolerating ``None`` and bytes."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _outcome_parts(outcome: RunnerOutcome) -> tuple[int, str]:
    """Return ``(exit_code, stdout_text)`` from a runner outcome.

    Raises:
        AnalysisError: the outcome's ``returncode`` is not an ``int`` -- a
            runner that does not honour the injection contract.
    """
    returncode = outcome.returncode
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise AnalysisError(
            f"runner returned a non-int returncode, got {type(returncode).__name__}: "
            f"{returncode!r}"
        )
    return returncode, _as_text(outcome.stdout)


def run_breakpoints(
    path: str | Path,
    info: BinaryInfo,
    addresses: Iterable[int],
    *,
    max_hits: int = DEFAULT_MAX_HITS,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
    script_dir: Path | None = None,
) -> GdbRunResult:
    """Build the gdb script, run it, and return the parsed trace report.

    The script is generated with
    :func:`codevanta.analysis.dynamic.build_gdb_script` (which validates every
    input and raises :class:`~codevanta.core.report.AnalysisError` on an empty
    or non-``int`` address list, an address outside an executable section, or
    an out-of-range ``max_hits``), written to ``script_dir`` or to a private
    temporary directory, executed as
    ``("gdb", "-q", "-batch", "-x", <script>, "--args", str(path))`` through
    ``runner`` (``subprocess.run`` by default), and its captured stdout is
    parsed with :func:`codevanta.analysis.trace.parse_gdb_trace`, attributing
    every hit to a candidate from
    :func:`codevanta.core.functions.discover_functions`.

    Args:
        path: Target binary, spelled the way gdb should see it.
        info: Binary metadata for the script's registers and section checks,
            and for function attribution in the parsed report.
        addresses: Breakpoint addresses, in file virtual-address space.
        max_hits: Hit ceiling the *script* enforces; the parser keeps
            everything the session printed.
        timeout: Wall-clock budget for the session, in seconds. Exceeding it
            raises :class:`~codevanta.core.report.AnalysisError`.
        runner: Injectable replacement for ``subprocess.run``; see the module
            docstring for the exact contract. ``None`` means
            ``subprocess.run``.
        script_dir: Directory to write the session script into, instead of a
            private temporary directory. The script file is removed after the
            run either way; the directory itself and its other contents are
            left alone.

    Raises:
        AnalysisError: A missing gdb executable, a session that exceeded
            ``timeout``, any script-validation failure (bad addresses, bad
            ``max_hits``), or a runner whose outcome violates the injection
            contract -- each message names what is missing or wrong.

    Returns:
        The parsed :class:`~codevanta.analysis.trace.TraceReport` wrapped in a
        :class:`GdbRunResult` with the exit code, the executed ``argv`` and
        any run-level warnings.
    """
    _require_timeout(timeout)
    script = build_gdb_script(path, info, addresses, max_hits=max_hits)
    execute = runner if runner is not None else _default_runner
    warnings: list[str] = []
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    script_path: Path | None = None
    try:
        if script_dir is None:
            temp_dir = tempfile.TemporaryDirectory(prefix="codevanta-gdb-")
            directory = Path(temp_dir.name)
        else:
            directory = Path(script_dir)
            directory.mkdir(parents=True, exist_ok=True)
        script_path = directory / script_file_name("gdb")
        script_path.write_text(script.text, encoding="utf-8", newline="\n")
        command = ("gdb", "-q", "-batch", "-x", str(script_path), "--args", str(path))
        try:
            outcome = execute(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AnalysisError(
                f"gdb session exceeded its timeout of {timeout} seconds and was terminated; "
                "raise timeout or reduce the breakpoint workload"
            ) from exc
        except FileNotFoundError as exc:
            raise AnalysisError(
                "gdb was not found: the runner raised FileNotFoundError, so the gdb "
                "executable is missing; install gdb and make sure it is on PATH "
                "(gdb_available() reports whether it is)"
            ) from exc
        exit_code, stdout = _outcome_parts(outcome)
        if exit_code != 0:
            warnings.append(
                f"gdb exited with non-zero code {exit_code}; its output was still parsed"
            )
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
        elif script_path is not None:
            try:
                script_path.unlink()
            except OSError as exc:
                warnings.append(f"the session script could not be removed: {exc}")

    report = parse_gdb_trace(stdout, info=info, functions=discover_functions(info))
    return GdbRunResult(
        report=report,
        exit_code=exit_code,
        script_path=str(script_path),
        command=command,
        raw_output_path=None,
        warnings=tuple(warnings),
    )


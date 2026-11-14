"""WASM bridge: wabt parsers (validate/objdump) plus two skip-gated runners.

The adb/sigrok pattern applied to WebAssembly modules: everything that
*understands* wabt output is a pure parser (:func:`parse_wasm_validate_stderr`
and :func:`parse_wasm_objdump`), fully tested offline against canned
transcripts, and everything that *runs* wabt is a thin wrapper
(:func:`wasm_validate`, :func:`wasm_objdump`) gated on one
``shutil.which`` probe per executable with a bounded timeout. On a machine
without wabt the parsers still run and the wrappers still import; they fail
with the typed missing-tool error naming the wabt release page -- never a
traceback. A module that *fails* validation is not a tool failure: it comes
back as ``valid=False`` with the parsed error lines.
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
    "MAX_ERRORS",
    "MAX_INSTRUCTIONS",
    "MAX_TIMEOUT",
    "WABT_MISSING_MESSAGE",
    "WasmInstruction",
    "WasmObjdumpResult",
    "WasmSection",
    "WasmValidateResult",
    "parse_wasm_objdump",
    "parse_wasm_validate_stderr",
    "wasm_available",
    "wasm_objdump",
    "wasm_validate",
]

#: Default wall-clock budget for one wabt invocation, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one wabt invocation.
MAX_TIMEOUT = 120.0

#: Validation error lines kept from one stderr transcript (bounded work).
MAX_ERRORS = 32

#: First instructions kept from one ``wasm-objdump -d`` transcript (bounded).
MAX_INSTRUCTIONS = 128

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "bridge.wabt"

#: Executables the lane needs (validation uses the first, disassembly the second).
WASM_VALIDATE = "wasm-validate"
WASM_OBJDUMP = "wasm-objdump"

#: Typed failure for the wrappers when wabt is absent, with install hint.
WABT_MISSING_MESSAGE = (
    "wabt is not on PATH; install the WebAssembly Binary Toolkit from "
    "https://github.com/WebAssembly/wabt/releases and make sure wasm-validate "
    "and wasm-objdump are on PATH"
)

#: ``file.wasm:00000be: error: ...`` -- one wasm-validate diagnostic line.
_WABT_ERROR = re.compile(r"(?P<where>[^\s:]+(?::[0-9a-fA-F]+)?):\s*error:\s*(?P<rest>.+)$")

#: `` Type start=0x0000000b end=0x00000014 (size=0x00000009) count: 1`` --
#: one wasm-objdump section header.
_WABT_SECTION = re.compile(
    r"^\s+(?P<name>[A-Za-z][\w ]*?)\s+start=0x(?P<start>[0-9a-fA-F]+)\s+"
    r"end=0x(?P<end>[0-9a-fA-F]+)\s+\(size=0x(?P<size>[0-9a-fA-F]+)\)"
)

#: `` 00000d: 01 41 01                   i32.const 1`` -- one disassembled
#: instruction (address, raw bytes, decoded text).
_WABT_INSTRUCTION = re.compile(
    r"^\s*(?P<offset>[0-9a-fA-F]{4,}):\s+(?P<raw>[0-9a-fA-F][0-9a-fA-F ]*?)\s{2,}"
    r"(?P<text>\S.*)$"
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
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _tail(text: str, limit: int = 400) -> str:
    """Return the last ``limit`` characters of ``text``, whitespace-flattened."""
    flat = " ".join(text.split())
    return flat[-limit:] if len(flat) > limit else flat
@dataclass(frozen=True)
class WasmSection:
    """One module section header reported by ``wasm-objdump -h``/``-d``."""

    name: str
    start: int | None = None
    end: int | None = None
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.start is not None:
            data["start"] = self.start
        if self.end is not None:
            data["end"] = self.end
        if self.size is not None:
            data["size"] = self.size
        return data


@dataclass(frozen=True)
class WasmInstruction:
    """One disassembled instruction row from ``wasm-objdump -d``."""

    offset: int
    raw_bytes: str
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"offset": self.offset, "bytes": self.raw_bytes, "text": self.text}


@dataclass(frozen=True)
class WasmValidateResult:
    """Verdict of one ``wasm-validate`` run plus its parsed error lines."""

    path: str
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="wasm-validate",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class WasmObjdumpResult:
    """Bounded parse of one ``wasm-objdump -d`` transcript."""

    path: str
    sections: tuple[WasmSection, ...] = ()
    instructions: tuple[WasmInstruction, ...] = ()
    truncated: bool = False
    transcript_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="wasm-objdump -d",
            confidence=Confidence.HIGH,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sections": [section.to_dict() for section in self.sections],
            "instructions": [instruction.to_dict() for instruction in self.instructions],
            "instruction_count": len(self.instructions),
            "truncated": self.truncated,
            "transcript_path": self.transcript_path,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

def parse_wasm_validate_stderr(text: Any) -> tuple[str, ...]:
    """Parse ``wasm-validate`` stderr into bounded typed error lines.

    Diagnostic lines look like ``file.wasm:00000be: error: ...``; other
    chatter (usage banners, blank lines) is dropped. Bounded at
    :data:`MAX_ERRORS`; anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"stderr must be a string, got {type(text).__name__}")
    errors: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _WABT_ERROR.search(stripped)
        if match is None:
            continue
        errors.append(f"{match.group('where')}: error: {match.group('rest').strip()}")
        if len(errors) >= MAX_ERRORS:
            break
    return tuple(errors)


def parse_wasm_objdump(
    text: Any,
) -> tuple[tuple[WasmSection, ...], tuple[WasmInstruction, ...], bool, list[str]]:
    """Parse ``wasm-objdump -d`` output into bounded sections + instructions.

    Section headers become :class:`WasmSection` rows; ``<offset>: <bytes>
    <decoded>`` lines become :class:`WasmInstruction` rows, bounded at
    :data:`MAX_INSTRUCTIONS` (``truncated`` reports the drop). Junk lines
    become warnings; anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    sections: list[WasmSection] = []
    instructions: list[WasmInstruction] = []
    warnings: list[str] = []
    truncated = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        section = _WABT_SECTION.match(stripped)
        if section is not None:
            sections.append(
                WasmSection(
                    name=section.group("name").strip(),
                    start=int(section.group("start"), 16),
                    end=int(section.group("end"), 16),
                    size=int(section.group("size"), 16),
                )
            )
            continue
        instruction = _WABT_INSTRUCTION.match(stripped)
        if instruction is not None:
            if len(instructions) >= MAX_INSTRUCTIONS:
                truncated = True
                _note(
                    warnings,
                    f"instruction limit {MAX_INSTRUCTIONS} reached; further rows dropped",
                )
                break
            instructions.append(
                WasmInstruction(
                    offset=int(instruction.group("offset"), 16),
                    raw_bytes=" ".join(instruction.group("raw").split()),
                    text=instruction.group("text").strip(),
                )
            )
            continue
        _note(warnings, f"unrecognised line skipped: {stripped.strip()[:64]!r}")
    return tuple(sections), tuple(instructions), truncated, warnings


def _check_timeout(value: Any) -> float:
    """Validate one wall-clock budget; the wrappers share the bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"timeout must be a number of seconds, got {value!r}")
    timeout = float(value)
    if not 1.0 <= timeout <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout {timeout} is out of range; expected 1 .. {MAX_TIMEOUT} seconds"
        )
    return timeout


def wasm_available() -> bool:
    """Report whether both wabt executables are on ``PATH``."""
    return shutil.which(WASM_VALIDATE) is not None and shutil.which(WASM_OBJDUMP) is not None


def _run_wabt(
    command: tuple[str, ...],
    *,
    timeout: float,
    runner: Runner | None,
) -> tuple[int, str, str]:
    """Run one bounded wabt invocation; return ``(code, stdout, stderr)``."""
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"{command[0]} exceeded its timeout of {timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{WABT_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
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
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return (
        returncode,
        stdout if isinstance(stdout, str) else "",
        stderr if isinstance(stderr, str) else "",
    )

def wasm_validate(
    input_path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
    which: Any = None,
) -> WasmValidateResult:
    """Run ``wasm-validate <file>`` and report the typed verdict.

    Skip-gated: without ``wasm-validate`` on ``PATH`` (and no injected
    ``runner``) this raises the typed :data:`WABT_MISSING_MESSAGE` error
    before any process is spawned. A module that fails validation is a
    *successful tool run*: the result carries ``valid=False`` plus the parsed
    error lines, not an exception. Exit codes other than 0/1 (tool crashes,
    usage errors) raise the typed error.
    """
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"WASM file not found: {target}")
    checked_timeout = _check_timeout(timeout)
    which_fn = which if which is not None else shutil.which
    if runner is None and which_fn(WASM_VALIDATE) is None:
        raise AnalysisError(WABT_MISSING_MESSAGE)
    code, stdout, stderr = _run_wabt(
        (WASM_VALIDATE, str(target)), timeout=checked_timeout, runner=runner
    )
    errors = parse_wasm_validate_stderr(stderr)
    if code not in (0, 1):
        raise AnalysisError(
            f"{WASM_VALIDATE} exited with code {code}: {_tail(stdout) or _tail(stderr) or 'no output'}"
        )
    valid = code == 0
    return WasmValidateResult(
        path=str(target),
        valid=valid,
        errors=errors,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="wasm-validate",
            confidence=Confidence.HIGH,
            detail="module validated" if valid else f"{len(errors)} validation error(s)",
        ),
    )


def wasm_objdump(
    input_path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
    which: Any = None,
    out_dir: str | Path | None = None,
) -> WasmObjdumpResult:
    """Run ``wasm-objdump -d <file>`` and parse sections + instructions.

    Skip-gated on ``wasm-objdump`` exactly like :func:`wasm_validate`; the
    instruction list is bounded at :data:`MAX_INSTRUCTIONS` (``truncated``
    reports the drop). With ``out_dir`` the raw transcript is preserved as
    ``wasm-objdump.txt`` next to the parsed result.
    """
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"WASM file not found: {target}")
    checked_timeout = _check_timeout(timeout)
    which_fn = which if which is not None else shutil.which
    if runner is None and which_fn(WASM_OBJDUMP) is None:
        raise AnalysisError(WABT_MISSING_MESSAGE)
    code, stdout, stderr = _run_wabt(
        (WASM_OBJDUMP, "-d", str(target)), timeout=checked_timeout, runner=runner
    )
    if code != 0:
        raise AnalysisError(
            f"{WASM_OBJDUMP} exited with code {code}: "
            f"{_tail(stderr) or _tail(stdout) or 'no output'}"
        )
    sections, instructions, truncated, warnings = parse_wasm_objdump(stdout)
    transcript_path: str | None = None
    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        transcript_file = out_path / "wasm-objdump.txt"
        transcript_file.write_text(stdout, encoding="utf-8")
        transcript_path = str(transcript_file)
    return WasmObjdumpResult(
        path=str(target),
        sections=sections,
        instructions=instructions,
        truncated=truncated,
        transcript_path=transcript_path,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="wasm-objdump -d",
            confidence=Confidence.HIGH,
            detail=f"{len(sections)} section(s), {len(instructions)} instruction(s)",
        ),
    )


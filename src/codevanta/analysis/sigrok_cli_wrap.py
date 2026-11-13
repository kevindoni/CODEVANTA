"""sigrok-cli wrapper: pure output parser plus one skip-gated live call.

The adb/gdb pattern applied to logic-capture decoding: everything that
*understands* sigrok-cli is the pure :func:`parse_sigrok_output` function,
fully tested offline against canned transcripts, and everything that *runs*
sigrok-cli is :func:`decode_with_sigrok`, gated on a single
``shutil.which("sigrok-cli")`` probe. On a machine without sigrok-cli the
parser still runs and the wrapper still imports; it fails with the typed
:class:`~codevanta.core.report.AnalysisError` carrying the install hint --
never a traceback, never a partial decode.

sigrok-cli's ``-P`` decoder output is plain text, one annotation per line::

    uart: 1234-1245: TX DATA: 41 'A'   (sample-range form)
    uart: 115200 baud, 8N1             (plain form)

Records are kept up to :data:`MAX_RECORDS`; junk lines become warnings.
Parser verdicts are honest: :data:`Confidence.MEDIUM`, because a decoder
plug-in's annotations are a third party's interpretation, not file structure.
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
    "MAX_RECORDS",
    "MAX_TIMEOUT",
    "SIGROK_MISSING_MESSAGE",
    "SigrokAnnotation",
    "SigrokDecodeResult",
    "decode_with_sigrok",
    "parse_sigrok_output",
    "sigrok_available",
]

#: Default wall-clock budget for one sigrok-cli invocation, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Hard ceiling on the wall-clock budget of one sigrok-cli invocation.
MAX_TIMEOUT = 120.0

#: Decoded annotation records kept from one transcript (bounded work).
MAX_RECORDS = 128

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Decoder names sigrok accepts (``uart``, ``i2c``, ``sdram_timing_scramble``...).
_DECODER_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")

#: ``1234-1245: rest`` -- the sample-range prefix of an annotation line.
_RANGE_PREFIX = re.compile(r"^(?P<start>\d+)-(?P<end>\d+):\s?(?P<rest>.*)$")

#: ``uart`` -- a decoder name heading one annotation line.
_DECODER_PREFIX = re.compile(r"^(?P<decoder>[A-Za-z0-9_.+-]+):\s?(?P<rest>.*)$")

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "sig.cli"

#: Typed failure for the wrapper when sigrok-cli is absent, with install hint.
SIGROK_MISSING_MESSAGE = (
    "sigrok-cli is not on PATH; install sigrok-cli from https://sigrok.org/wiki/"
    "Downloads and make sure it is on PATH"
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
class SigrokAnnotation:
    """One decoded annotation row from a sigrok-cli transcript."""

    decoder: str
    text: str
    start_sample: int | None = None
    end_sample: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"decoder": self.decoder, "text": self.text}
        if self.start_sample is not None:
            data["start_sample"] = self.start_sample
        if self.end_sample is not None:
            data["end_sample"] = self.end_sample
        return data


@dataclass(frozen=True)
class SigrokDecodeResult:
    """Bounded, evidence-backed parse of one sigrok-cli decode transcript."""

    records: tuple[SigrokAnnotation, ...] = ()
    truncated: bool = False
    transcript_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="sigrok-cli -P",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [record.to_dict() for record in self.records],
            "count": len(self.records),
            "truncated": self.truncated,
            "transcript_path": self.transcript_path,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_sigrok_output(text: Any) -> SigrokDecodeResult:
    """Parse sigrok-cli decoder output into bounded typed records.

    Lines that do not start with a decoder name are junk (banners, channel
    chatter) and become warnings; the parse itself never raises for
    transcript content. Anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    records: list[SigrokAnnotation] = []
    warnings: list[str] = []
    truncated = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue  # sigrok-cli status chatter
        heading = _DECODER_PREFIX.match(stripped)
        if heading is None:
            _note(warnings, f"unrecognised line skipped: {stripped[:64]!r}")
            continue
        decoder = heading.group("decoder")
        rest = heading.group("rest")
        ranged = _RANGE_PREFIX.match(rest)
        if ranged is not None:
            records.append(
                SigrokAnnotation(
                    decoder=decoder,
                    text=ranged.group("rest"),
                    start_sample=int(ranged.group("start")),
                    end_sample=int(ranged.group("end")),
                )
            )
        else:
            records.append(SigrokAnnotation(decoder=decoder, text=rest))
        if len(records) >= MAX_RECORDS:
            truncated = True
            _note(warnings, f"record limit {MAX_RECORDS} reached; further rows dropped")
            break
    if not records and not warnings:
        _note(warnings, "no decoder output lines in the transcript")
    return SigrokDecodeResult(
        records=tuple(records),
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="sigrok-cli -P",
            confidence=Confidence.MEDIUM,
            detail=f"{len(records)} annotation record(s)",
        ),
    )


def sigrok_available() -> bool:
    """Report whether sigrok-cli is on ``PATH``; the only gate a caller needs."""
    return _sigrok_path() is not None


def _sigrok_path() -> str | None:
    """Probe ``PATH`` for sigrok-cli; nothing else can fail here."""
    return shutil.which("sigrok-cli")


def _require_sigrok() -> None:
    """Raise the typed skip-gate failure when sigrok-cli is absent."""
    if _sigrok_path() is None:
        raise AnalysisError(SIGROK_MISSING_MESSAGE)


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


def _check_decoder(decoder: Any) -> str:
    """Validate one decoder name before it reaches argv."""
    if not isinstance(decoder, str):
        raise AnalysisError(f"decoder must be a string, got {type(decoder).__name__}")
    name = decoder.strip()
    if not _DECODER_RE.match(name):
        raise AnalysisError(
            f"decoder {decoder!r} is not a sigrok decoder name; expected letters, "
            "digits and . _ + - only"
        )
    return name


def decode_with_sigrok(
    input_path: str | Path,
    decoder: str,
    *,
    out_dir: str | Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> SigrokDecodeResult:
    """Run ``sigrok-cli -i <input> -P <decoder>`` and parse its transcript.

    Skip-gated: without sigrok-cli on ``PATH`` (and no injected ``runner``)
    this raises the typed :data:`SIGROK_MISSING_MESSAGE` error before any
    process is spawned. With ``out_dir`` the raw transcript is preserved at
    ``<out_dir>/sigrok-<decoder>.txt`` next to the parsed result.
    """
    checked_decoder = _check_decoder(decoder)
    if not isinstance(input_path, (str, Path)):
        raise AnalysisError(
            f"input_path must be a str or Path, got {type(input_path).__name__}"
        )
    target = Path(input_path)
    if not target.is_file():
        raise AnalysisError(f"capture file not found: {target}")
    checked_timeout = _check_timeout(timeout)
    if runner is None:
        _require_sigrok()
    command: tuple[str, ...] = ("sigrok-cli", "-i", str(target), "-P", checked_decoder)
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked_timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"sigrok-cli -P {checked_decoder} exceeded its timeout of "
            f"{checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{SIGROK_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
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
            f"sigrok-cli exited with code {returncode}: "
            f"{_tail(stderr_text) or 'no stderr output'}"
        )
    result = parse_sigrok_output(stdout if isinstance(stdout, str) else "")
    if out_dir is not None:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", checked_decoder)
        transcript = out_path / f"sigrok-{safe_name}.txt"
        transcript.write_text(stdout if isinstance(stdout, str) else "", encoding="utf-8")
        result = SigrokDecodeResult(
            records=result.records,
            truncated=result.truncated,
            transcript_path=str(transcript),
            warnings=result.warnings,
            evidence=result.evidence,
        )
    return result



"""apktool wrapper: pure output parsers plus one skip-gated live decode.

The adb/gdb/sigrok pattern applied to Android resources: everything that
*understands* apktool is a pure function -- :func:`parse_apktool_console`
reads the tool's transcript and :func:`summarize_decode_dir` shallow-walks
the tree apktool wrote -- and everything that *runs* apktool is
:func:`apk_decode`, gated on a single ``shutil.which("apktool")`` probe with
a bounded timeout. On a machine without apktool the parsers still run and
the wrapper still imports; it fails with the typed
:class:`~codevanta.core.report.AnalysisError` carrying the install hint and
a pointer to the offline ``codevanta metadata`` fallback -- never a
traceback, never a partial decode.

The decode runs ``apktool d --no-src -f``: resources and
``AndroidManifest.xml`` are decoded, sources are deliberately not
baksmali'd, so ``smali/`` directories are *expected* to be absent (the
summary reports them honestly rather than failing). Console records and
directory entries are kept up to :data:`MAX_ENTRIES`; junk lines and
surprises become warnings.
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
    "APKTOOL_MISSING_MESSAGE",
    "ApkDecodeSummary",
    "ApktoolConsole",
    "ApktoolMessage",
    "DEFAULT_TIMEOUT",
    "EVIDENCE_SOURCE",
    "MAX_ENTRIES",
    "MAX_TIMEOUT",
    "apk_available",
    "apk_decode",
    "parse_apktool_console",
    "summarize_decode_dir",
]

#: Default wall-clock budget for one apktool invocation, in seconds.
DEFAULT_TIMEOUT = 120.0

#: Hard ceiling on the wall-clock budget of one apktool invocation.
MAX_TIMEOUT = 120.0

#: Bounded work: console messages kept, directory entries named, res/ files
#: counted. Everything past the cap is summarised as ``truncated``.
MAX_ENTRIES = 64

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "bridge.apktool"

#: Typed failure for the wrapper when apktool is absent, with install hint
#: and the offline ``codevanta metadata`` fallback pointer.
APKTOOL_MISSING_MESSAGE = (
    "apktool is not on PATH; install it from https://apktool.org "
    "(Java required) and make sure it is on PATH, or use "
    "`codevanta metadata <apk>` for the offline signing-block fallback"
)

#: ``I: Using Apktool 2.9.3 on demo.apk`` -- version plus target line.
_APKTOOL_BANNER = re.compile(
    r"^Using Apktool (?P<version>[0-9][A-Za-z0-9_.-]*) on (?P<apk>.+)$"
)

#: ``I: Decoding AndroidManifest.xml ...`` -- one level-prefixed console line.
_LEVEL_PREFIX = re.compile(r"^(?P<level>[IWE]):\s?(?P<text>.*)$")

#: Top-level directory names that are smali sources (``smali``,
#: ``smali_classes2``, ...). ``--no-src`` keeps every one of them absent.
_SMALI_PREFIX = "smali"


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
class ApktoolMessage:
    """One level-prefixed line from an apktool transcript."""

    level: str
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "text": self.text}


@dataclass(frozen=True)
class ApktoolConsole:
    """Bounded, evidence-backed parse of one apktool console transcript."""

    messages: tuple[ApktoolMessage, ...] = ()
    framework_version: str | None = None
    apk_name: str | None = None
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="parse_apktool_console",
            confidence=Confidence.MEDIUM,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages": [message.to_dict() for message in self.messages],
            "count": len(self.messages),
            "framework_version": self.framework_version,
            "apk_name": self.apk_name,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }
def parse_apktool_console(text: Any) -> ApktoolConsole:
    """Parse an apktool console transcript into bounded typed messages.

    ``I:``/``W:``/``E:``-prefixed lines become :class:`ApktoolMessage`
    records; the ``Using Apktool <version> on <apk>`` banner is lifted into
    structured fields. Any other line is junk (banners from Java, progress
    chatter) and becomes a warning. The parse itself never raises for
    transcript content; anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"transcript must be a string, got {type(text).__name__}")
    messages: list[ApktoolMessage] = []
    warnings: list[str] = []
    truncated = False
    framework_version: str | None = None
    apk_name: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        prefix = _LEVEL_PREFIX.match(stripped)
        if prefix is not None:
            if len(messages) >= MAX_ENTRIES:
                truncated = True
                _note(warnings, f"message limit {MAX_ENTRIES} reached; further lines dropped")
                break
            body = prefix.group("text")
            banner = _APKTOOL_BANNER.match(body)
            if banner is not None:
                framework_version = banner.group("version")
                apk_name = banner.group("apk").strip()
            messages.append(ApktoolMessage(level=prefix.group("level"), text=body))
            continue
        _note(warnings, f"unrecognised line skipped: {stripped[:64]!r}")
    if not messages and not warnings:
        _note(warnings, "no apktool console lines in the transcript")
    return ApktoolConsole(
        messages=tuple(messages),
        framework_version=framework_version,
        apk_name=apk_name,
        truncated=truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="parse_apktool_console",
            confidence=Confidence.MEDIUM,
            detail=f"{len(messages)} console message(s)",
        ),
    )


@dataclass(frozen=True)
class ApkDecodeSummary:
    """Shallow, bounded walk of one apktool decode output tree."""

    apk: str
    out_dir: str
    manifest_decoded: bool = False
    apktool_yml: bool = False
    res_count: int = 0
    res_truncated: bool = False
    smali_present: bool = False
    entries: tuple[str, ...] = ()
    entries_truncated: bool = False
    framework_version: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="summarize_decode_dir",
            confidence=Confidence.HIGH,
        )
    )

    @property
    def smali_expected_absent(self) -> bool:
        """``True``: the decode ran ``--no-src``, so smali absence is by design."""
        return not self.smali_present

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk": self.apk,
            "out_dir": self.out_dir,
            "manifest_decoded": self.manifest_decoded,
            "apktool_yml": self.apktool_yml,
            "res_count": self.res_count,
            "res_truncated": self.res_truncated,
            "smali_present": self.smali_present,
            "smali_expected_absent": self.smali_expected_absent,
            "entries": list(self.entries),
            "entries_truncated": self.entries_truncated,
            "framework_version": self.framework_version,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }
def summarize_decode_dir(out_dir: str | Path) -> ApkDecodeSummary:
    """Shallow-walk an apktool output directory into a typed summary.

    Bounded work: at most :data:`MAX_ENTRIES` top-level entries are named and
    at most :data:`MAX_ENTRIES` files are counted under ``res/``. With
    ``--no-src`` no ``smali*/`` directory is produced; the summary reports
    ``smali_present=False`` as the expected outcome, not a failure.
    """
    root = Path(out_dir)
    if not root.is_dir():
        raise AnalysisError(f"decode output directory not found: {root}")
    warnings: list[str] = []
    names: list[str] = []
    entries_truncated = False
    smali_present = False
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        if child.name.startswith(_SMALI_PREFIX) and child.is_dir():
            smali_present = True
        if len(names) >= MAX_ENTRIES:
            entries_truncated = True
            _note(warnings, f"entry limit {MAX_ENTRIES} reached; further entries dropped")
            break
        names.append(child.name)
    res_count = 0
    res_truncated = False
    res_dir = root / "res"
    if res_dir.is_dir():
        for path in res_dir.rglob("*"):
            if not path.is_file():
                continue
            if res_count >= MAX_ENTRIES:
                res_truncated = True
                _note(warnings, f"res/ file limit {MAX_ENTRIES} reached; count stopped")
                break
            res_count += 1
    else:
        _note(warnings, "no res/ directory in the decode output")
    manifest_decoded = (root / "AndroidManifest.xml").is_file()
    return ApkDecodeSummary(
        apk="",
        out_dir=str(root),
        manifest_decoded=manifest_decoded,
        apktool_yml=(root / "apktool.yml").is_file(),
        res_count=res_count,
        res_truncated=res_truncated,
        smali_present=smali_present,
        entries=tuple(names),
        entries_truncated=entries_truncated,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="summarize_decode_dir",
            confidence=Confidence.HIGH,
            detail=(
                f"manifest={'yes' if manifest_decoded else 'no'}, "
                f"res={res_count} file(s), smali={'yes' if smali_present else 'no'}"
            ),
        ),
    )


def apk_available() -> bool:
    """Report whether apktool is on ``PATH``; the only gate a caller needs."""
    return _apktool_path() is not None


def _apktool_path() -> str | None:
    """Probe ``PATH`` for apktool; nothing else can fail here."""
    return shutil.which("apktool")


def apk_decode(
    apk_path: str | Path,
    out_dir: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
) -> ApkDecodeSummary:
    """Run ``apktool d --no-src -f`` and walk the decoded tree.

    Skip-gated: without apktool on ``PATH`` (and no injected ``runner``) this
    raises the typed :data:`APKTOOL_MISSING_MESSAGE` error before any process
    is spawned. The console transcript is parsed into bounded records and the
    output directory is shallow-walked (manifest, ``apktool.yml``, bounded
    ``res/`` count, smali absence, bounded entry names) into one
    :class:`ApkDecodeSummary`.
    """
    target = _check_path(apk_path, "apk_path")
    if not target.is_file():
        raise AnalysisError(f"APK file not found: {target}")
    destination = _check_path(out_dir, "out_dir")
    checked_timeout = _check_timeout(timeout)
    if runner is None:
        _require_apktool()
    destination.mkdir(parents=True, exist_ok=True)
    command: tuple[str, ...] = (
        "apktool",
        "d",
        "--no-src",
        "-f",
        "-o",
        str(destination),
        str(target),
    )
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=checked_timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"apktool d exceeded its timeout of {checked_timeout} seconds and was terminated"
        ) from exc
    except FileNotFoundError as exc:
        raise AnalysisError(
            f"{APKTOOL_MISSING_MESSAGE}; the runner raised FileNotFoundError, so the "
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
            f"apktool exited with code {returncode}: {_tail(stderr_text) or 'no stderr output'}"
        )
    console = parse_apktool_console(stdout if isinstance(stdout, str) else "")
    summary = summarize_decode_dir(destination)
    warnings = summary.warnings
    for note in console.warnings:
        _note(warnings, note)
    return ApkDecodeSummary(
        apk=str(target),
        out_dir=summary.out_dir,
        manifest_decoded=summary.manifest_decoded,
        apktool_yml=summary.apktool_yml,
        res_count=summary.res_count,
        res_truncated=summary.res_truncated,
        smali_present=summary.smali_present,
        entries=summary.entries,
        entries_truncated=summary.entries_truncated,
        framework_version=console.framework_version,
        warnings=warnings,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="apktool d --no-src",
            confidence=Confidence.HIGH,
            detail=(
                f"apktool {console.framework_version or '?'} decoded "
                f"{summary.res_count} res/ file(s) into {summary.out_dir}"
            ),
        ),
    )


def _require_apktool() -> None:
    """Raise the typed skip-gate failure when apktool is absent."""
    if _apktool_path() is None:
        raise AnalysisError(APKTOOL_MISSING_MESSAGE)


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


"""JEB headless bridge: a parse-first, skip-gated wrapper around a paid tool.

JEB (PNF Software) is a **commercial** DEX/APK decompiler. Nothing here pretends
otherwise: :func:`probe_jeb` looks for a launcher (``jeb``, ``jeb_linux.sh``,
``jeb_macos.sh``, ``jeb.exe`` on ``PATH``, or one of those inside ``JEB_HOME``)
and, when it finds none, returns a typed :class:`JebCapability` whose reason
says *"JEB is commercial; install it and set JEB_HOME"*. No download, no
extraction, no license handling -- a machine without JEB simply gets
``available=False``.

The lane follows the adb/sigrok/objdump pattern exactly:

* everything that *understands* JEB's output is the pure
  :func:`parse_jeb_output` function, canned-tested offline against a
  hand-written headless transcript;
* everything that *runs* JEB is :func:`decompile_dex`, gated on the probe,
  bounded by a wall-clock timeout (:data:`DEFAULT_TIMEOUT`, hard ceiling
  :data:`MAX_TIMEOUT`), with stdout capped at :data:`MAX_LINES` lines before
  parsing;
* the runner is injectable (:class:`Runner`) so every branch of the wrapper --
  success, nonzero exit, timeout, missing executable -- is testable with no JEB
  installation at all.

Headless contract
-----------------
JEB is driven in its documented client-script mode::

    jeb_linux.sh --script codevanta_jeb_export.py -- target.dex

The script is the built-in :data:`JEB_SCRIPT` string (written next to the run,
never downloaded), and its output contract is three line markers:

``@@class <signature>``
    starts a class;
``@@method <signature>``
    starts a method of the current class;
``@@end``
    closes the current method.

Every other non-blank line is pseudocode of the current method. That is the
whole format, so the parser stays small, bounded
(:data:`MAX_CLASSES` / :data:`MAX_METHODS` / :data:`MAX_PSEUDOCODE_LINES`) and
honest about noise: anything it cannot place becomes a warning, and output with
no class marker at all is the typed :class:`~codevanta.core.report.AnalysisError`
rather than an empty result.

Scope note: JEB renders *classes*, not arbitrary addresses, so this bridge is
deliberately not an address-level decompiler provider. The routing layer
(:mod:`codevanta.analysis.decompile_router`) only nominates JEB for ``.dex`` and
``.apk`` targets.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "COMMERCIAL_NOTE",
    "DEFAULT_TIMEOUT",
    "DEX_SUFFIXES",
    "EVIDENCE_SOURCE",
    "EXECUTABLES",
    "JEB_HOME_ENV",
    "JEB_SCRIPT",
    "MAX_CLASSES",
    "MAX_LINES",
    "MAX_METHODS",
    "MAX_PSEUDOCODE_LINES",
    "MAX_TIMEOUT",
    "PROBE_TIMEOUT",
    "JebCapability",
    "JebClass",
    "JebDecompilation",
    "JebMethod",
    "decompile_dex",
    "parse_jeb_output",
    "probe_jeb",
]


#: Wall-clock budget for the single bounded ``--version`` probe call, in seconds.
PROBE_TIMEOUT = 5.0

#: Default wall-clock budget for one headless JEB run, in seconds.
DEFAULT_TIMEOUT = 120.0

#: Hard ceiling on the wall-clock budget of one headless JEB run, in seconds.
MAX_TIMEOUT = 600.0

#: Output lines kept from one headless run (the bounded-work cap).
MAX_LINES = 512

#: Classes kept per decompilation.
MAX_CLASSES = 64

#: Methods kept per class.
MAX_METHODS = 64

#: Pseudocode lines kept per method (a preview, not the whole function).
MAX_PSEUDOCODE_LINES = 40

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: Environment variable that may point at a JEB installation directory.
JEB_HOME_ENV = "JEB_HOME"

#: Launcher names probed on ``PATH`` and inside ``JEB_HOME``.
EXECUTABLES: tuple[str, ...] = ("jeb", "jeb_linux.sh", "jeb_macos.sh", "jeb.exe")

#: Targets JEB can render (class-level decompilation only).
DEX_SUFFIXES: tuple[str, ...] = (".dex", ".apk")

#: The honest note every absent-JEB reason ends with.
COMMERCIAL_NOTE = "JEB is commercial; install it and set JEB_HOME"

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "decompile.jeb"

#: Evidence ``method`` label for the headless script run.
EVIDENCE_METHOD = "jeb_headless_script"

#: Line marker that starts a class in the headless output.
MARKER_CLASS = "@@class "

#: Line marker that starts a method of the current class.
MARKER_METHOD = "@@method "

#: Line marker that closes the current method.
MARKER_END = "@@end"

#: Built-in JEB client script (JEB 4 Python scripting API) that exports the
#: decompiled text of every class/method to stdout in the marker format above.
JEB_SCRIPT = """\
# CODEVANTA JEB headless export -- print decompiled pseudocode to stdout.
# Usage: jeb_linux.sh --script codevanta_jeb_export.py -- <target.dex|apk>
from com.pnfsoftware.jeb.client.api import IScript

MARK_CLASS = '@@class '
MARK_METHOD = '@@method '
MARK_END = '@@end'


class CodevantaJebExport(IScript):
    def run(self, ctx):
        for unit in ctx.getMainProject().getUnits():
            for cls in unit.getClasses():
                print(MARK_CLASS + cls.getSignature(False))
                for mth in cls.getMethods():
                    print(MARK_METHOD + mth.getSignature(False))
                    for line in mth.getDecompiledText().splitlines():
                        print(line)
                    print(MARK_END)
"""

#: Any ``major.minor`` / ``major.minor.patch`` token in a version banner.
_SEMVER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

#: Lines of a ``--version`` banner searched for a version token.
_VERSION_SCAN_LINES = 3


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


def _parse_version(banner: str) -> str | None:
    """Return the first version token of a JEB banner, tolerant of any format.

    JEB does not advertise ``--version`` on every build, so this never raises
    and never guesses: an unrecognisable banner is simply ``None``.
    """
    for line in banner.splitlines()[:_VERSION_SCAN_LINES]:
        match = _SEMVER_RE.search(line)
        if match is not None:
            return match.group(1)
    return None



@dataclass(frozen=True)
class JebCapability:
    """Whether JEB can be driven headlessly on this machine.

    Attributes:
        available: True when a JEB launcher was found (``PATH`` or ``JEB_HOME``).
        executable: Absolute path of the launcher, ``None`` when unavailable.
        version: Version parsed from the one bounded ``--version`` attempt,
            ``None`` when JEB printed no recognisable banner (it often does not).
        reason: Always a non-empty explanation -- the commercial/install note
            when unavailable, the headless-mode note when available.
    """

    available: bool
    executable: str | None = None
    version: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (the canonical payload for CLI/MCP consumers)."""
        return {
            "available": self.available,
            "executable": self.executable,
            "version": self.version,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class JebMethod:
    """One decompiled method: its signature plus a bounded pseudocode preview."""

    signature: str
    pseudocode: tuple[str, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view: the signature, the preview lines and the bound flag."""
        return {
            "signature": self.signature,
            "pseudocode": list(self.pseudocode),
            "lines": len(self.pseudocode),
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class JebClass:
    """One decompiled class with its bounded method list."""

    name: str
    methods: tuple[JebMethod, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view: the class name, its methods and the bound flag."""
        return {
            "name": self.name,
            "methods": [method.to_dict() for method in self.methods],
            "method_count": len(self.methods),
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class JebDecompilation:
    """A parsed JEB headless export: bounded classes, warnings and evidence."""

    target: str
    classes: tuple[JebClass, ...] = ()
    class_name: str | None = None
    method: str | None = None
    truncated: bool = False
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    @property
    def method_count(self) -> int:
        """Total methods across every kept class."""
        return sum(len(jeb_class.methods) for jeb_class in self.classes)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view of the whole export (evidence included when present)."""
        return {
            "target": self.target,
            "class_name": self.class_name,
            "method": self.method,
            "classes": [jeb_class.to_dict() for jeb_class in self.classes],
            "class_count": len(self.classes),
            "method_count": self.method_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
        }



def _launcher_candidates(which_fn: Any, environ: Mapping[str, str]) -> list[str]:
    """Return every JEB launcher candidate, ``JEB_HOME`` first, then ``PATH``.

    Order is deterministic (launcher order inside each location) and duplicates
    are dropped, so the same machine always probes the same executable first.
    """
    found: list[str] = []
    home = str(environ.get(JEB_HOME_ENV, "") or "").strip()
    if home:
        base = Path(home)
        for name in EXECUTABLES:
            candidate = base / name
            try:
                is_file = candidate.is_file()
            except OSError:  # pragma: no cover - unreadable JEB_HOME
                is_file = False
            if is_file:
                found.append(str(candidate))
    for name in EXECUTABLES:
        located = which_fn(name)
        if located and str(located) not in found:
            found.append(str(located))
    return found


def _probe_version(
    executable: str, runner: Runner | None
) -> tuple[str | None, str | None]:
    """Run exactly one bounded ``--version`` call; return ``(version, note)``.

    Never raises: a timeout, a missing binary, a nonzero exit or an
    unparseable banner all degrade into a note, because the presence of the
    launcher -- not its banner -- is what makes JEB available.
    """
    execute = runner if runner is not None else subprocess.run
    try:
        outcome = execute(
            (executable, "--version"), capture_output=True, text=True, timeout=PROBE_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return None, f"'{executable} --version' timed out after {PROBE_TIMEOUT:g}s"
    except FileNotFoundError:
        return None, f"'{executable}' vanished between the probe and the version call"
    except OSError as exc:
        return None, f"'{executable}' could not be executed: {exc}"
    returncode = getattr(outcome, "returncode", None)
    if isinstance(returncode, int) and returncode != 0:
        return None, f"'{executable} --version' exited with code {returncode}"
    stdout = getattr(outcome, "stdout", None)
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    banner = stdout if isinstance(stdout, str) else ""
    version = _parse_version(banner)
    if version is None:
        return None, (
            f"'{executable}' printed no recognisable version banner "
            "(JEB does not answer --version on every build)"
        )
    return version, None


def probe_jeb(
    *,
    which: Any = None,
    runner: Runner | None = None,
    environ: Mapping[str, str] | None = None,
) -> JebCapability:
    """Probe for a JEB launcher; never raises, never installs anything.

    Args:
        which: Injectable ``shutil.which`` stand-in (offline tests).
        runner: Injectable ``subprocess.run`` stand-in (offline tests).
        environ: Environment mapping probed for :data:`JEB_HOME_ENV`
            (defaults to ``os.environ``).

    Returns:
        The capability record. Absence is ``available=False`` plus a reason
        ending with the honest :data:`COMMERCIAL_NOTE`.
    """
    which_fn = which if which is not None else shutil.which
    environment = environ if environ is not None else os.environ
    candidates = _launcher_candidates(which_fn, environment)
    if not candidates:
        return JebCapability(
            available=False,
            executable=None,
            version=None,
            reason=(
                f"none of {', '.join(EXECUTABLES)} is on PATH and {JEB_HOME_ENV} "
                f"names no JEB launcher; {COMMERCIAL_NOTE}"
            ),
        )
    executable = candidates[0]
    version, note = _probe_version(executable, runner)
    reason = (
        f"'{executable}' found; JEB decompiles DEX/APK classes in headless script mode "
        f"({'version ' + version if version else note or 'version unknown'})"
    )
    return JebCapability(
        available=True, executable=executable, version=version, reason=reason
    )



def _check_filter(name: str, value: str | None) -> str | None:
    """Validate one optional class/method filter (a non-empty string or None)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise AnalysisError(f"{name} must be a string or None, got {type(value).__name__}")
    if not value.strip():
        raise AnalysisError(f"{name} must not be blank; omit it to keep everything")
    return value.strip()


def parse_jeb_output(
    text: Any,
    *,
    target: str = "",
    class_name: str | None = None,
    method: str | None = None,
) -> JebDecompilation:
    """Parse a JEB headless transcript into a bounded :class:`JebDecompilation`.

    The format is the marker contract documented at the top of this module
    (``@@class`` / ``@@method`` / ``@@end``); every other non-blank line is
    pseudocode of the current method. The parse is bounded three ways --
    :data:`MAX_CLASSES`, :data:`MAX_METHODS`, :data:`MAX_PSEUDOCODE_LINES` --
    and every bound, plus every line it could not place, becomes a warning.

    Args:
        text: The headless stdout transcript.
        target: Label recorded on the result (usually the DEX/APK path).
        class_name: Optional class filter (substring of the class signature).
        method: Optional method filter (substring of the method signature).

    Returns:
        The parsed, bounded and JSON-safe export.

    Raises:
        AnalysisError: If ``text`` is not a string, a filter is blank, the
            transcript contains no ``@@class`` marker at all (malformed or
            wrong script output), or a filter matched nothing.
    """
    if not isinstance(text, str):
        raise AnalysisError(
            f"JEB headless output must be a string, got {type(text).__name__}"
        )
    wanted_class = _check_filter("class_name", class_name)
    wanted_method = _check_filter("method", method)
    lines = text.splitlines()
    warnings: list[str] = []
    truncated = len(lines) > MAX_LINES
    if truncated:
        _note(warnings, f"headless output capped at {MAX_LINES} lines; further lines dropped")

    class_names: list[str] = []
    class_methods: list[list[JebMethod]] = []
    class_truncated: list[bool] = []
    saw_marker = False
    stopped = False
    stray_outside = 0
    position: int | None = None
    signature = ""
    preview: list[str] = []
    preview_truncated = False
    skipping = False

    def _close_method() -> None:
        nonlocal preview, preview_truncated, skipping, signature
        if position is not None and not skipping:
            class_methods[position].append(
                JebMethod(
                    signature=signature,
                    pseudocode=tuple(preview),
                    truncated=preview_truncated,
                )
            )
        preview = []
        preview_truncated = False
        skipping = False
        signature = ""

    for raw in lines[:MAX_LINES]:
        line = raw.rstrip()
        if line.startswith(MARKER_CLASS):
            saw_marker = True
            _close_method()
            name = line[len(MARKER_CLASS) :].strip()
            if len(class_names) >= MAX_CLASSES:
                truncated = True
                _note(
                    warnings,
                    f"class list capped at {MAX_CLASSES}; the remaining classes were dropped",
                )
                position = None
                stopped = True
                break
            if not name:
                _note(warnings, "a @@class marker had an empty name; class skipped")
                position = None
                continue
            class_names.append(name)
            class_methods.append([])
            class_truncated.append(False)
            position = len(class_names) - 1
            continue
        if line.startswith(MARKER_METHOD):
            saw_marker = True
            _close_method()
            if position is None:
                _note(warnings, "a @@method marker appeared outside any class; ignored")
                continue
            name = line[len(MARKER_METHOD) :].strip()
            if not name:
                _note(warnings, "a @@method marker had an empty signature; skipped")
                continue
            if len(class_methods[position]) >= MAX_METHODS:
                class_truncated[position] = True
                truncated = True
                _note(
                    warnings,
                    f"methods of class {class_names[position]!r} capped at {MAX_METHODS}",
                )
                skipping = True
                continue
            signature = name
            continue
        if line.startswith(MARKER_END):
            _close_method()
            continue
        if not line.strip():
            continue
        if position is None or (not signature and not skipping):
            stray_outside += 1
            continue
        if skipping:
            continue
        if len(preview) >= MAX_PSEUDOCODE_LINES:
            preview_truncated = True
            truncated = True
            _note(
                warnings,
                f"pseudocode of {signature!r} capped at {MAX_PSEUDOCODE_LINES} lines",
            )
            continue
        preview.append(line)


    if not stopped:
        _close_method()
    if stray_outside:
        _note(warnings, f"{stray_outside} line(s) outside any method were ignored")
    if not saw_marker:
        raise AnalysisError(
            "JEB headless output contained no @@class marker; expected the "
            f"{EVIDENCE_SOURCE} script contract -- check that --script ran JEB_SCRIPT"
        )

    classes = tuple(
        JebClass(
            name=name,
            methods=tuple(class_methods[index]),
            truncated=class_truncated[index],
        )
        for index, name in enumerate(class_names)
    )
    if wanted_class is not None or wanted_method is not None:
        classes = _apply_filters(classes, wanted_class, wanted_method)
    return JebDecompilation(
        target=target,
        classes=classes,
        class_name=wanted_class,
        method=wanted_method,
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="marker_parse",
            confidence=Confidence.MEDIUM,
            detail=(
                f"{len(classes)} class(es) and "
                f"{sum(len(jeb_class.methods) for jeb_class in classes)} method(s) parsed"
            ),
        ),
    )


def _apply_filters(
    classes: tuple[JebClass, ...], wanted_class: str | None, wanted_method: str | None
) -> tuple[JebClass, ...]:
    """Keep only the classes/methods whose signatures contain the filters."""
    kept: list[JebClass] = []
    for jeb_class in classes:
        if wanted_class is not None and wanted_class not in jeb_class.name:
            continue
        methods = jeb_class.methods
        if wanted_method is not None:
            methods = tuple(
                entry for entry in methods if wanted_method in entry.signature
            )
            if not methods:
                continue
        kept.append(replace(jeb_class, methods=methods))
    if not kept:
        wanted = " and ".join(
            part
            for part in (
                None if wanted_class is None else f"class containing {wanted_class!r}",
                None if wanted_method is None else f"method containing {wanted_method!r}",
            )
            if part is not None
        )
        raise AnalysisError(f"JEB produced no {wanted}")
    return tuple(kept)



def _check_timeout(timeout_s: Any) -> float:
    """Validate the wall-clock budget: a positive number up to :data:`MAX_TIMEOUT`."""
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        raise AnalysisError(
            f"timeout_s must be a number, got {type(timeout_s).__name__}"
        )
    value = float(timeout_s)
    if not 0 < value <= MAX_TIMEOUT:
        raise AnalysisError(
            f"timeout_s must be in (0, {MAX_TIMEOUT:g}], got {value:g}"
        )
    return value


def _write_script(directory: Path) -> Path:
    """Write the built-in :data:`JEB_SCRIPT` into ``directory`` and return the path."""
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "codevanta_jeb_export.py"
    script.write_text(JEB_SCRIPT, encoding="utf-8")
    return script


def decompile_dex(
    path: str | Path,
    class_name: str | None = None,
    method: str | None = None,
    out_dir: str | Path | None = None,
    timeout_s: float = DEFAULT_TIMEOUT,
    *,
    runner: Runner | None = None,
    which: Any = None,
    environ: Mapping[str, str] | None = None,
) -> JebDecompilation:
    """Run JEB headlessly on ``path`` and parse its decompiled pseudocode.

    JEB is driven as ``<launcher> --script <built-in script> -- <target>``; the
    script is written into ``out_dir`` (a temporary directory, removed
    afterwards, when ``out_dir`` is ``None``). Output is capped at
    :data:`MAX_LINES` lines before parsing and the run is bounded by
    ``timeout_s``.

    Args:
        path: ``.dex`` or ``.apk`` file; it is read by JEB, never by CODEVANTA.
        class_name: Optional class filter (substring of the class signature).
        method: Optional method filter (substring of the method signature).
        out_dir: Directory the export script is written into; ``None`` uses a
            temporary directory that is cleaned up.
        timeout_s: Wall-clock budget in seconds, ``(0, MAX_TIMEOUT]``.
        runner: Injectable ``subprocess.run`` stand-in (offline tests).
        which: Injectable ``shutil.which`` stand-in (offline tests).
        environ: Environment mapping probed for :data:`JEB_HOME_ENV`.

    Returns:
        The parsed, bounded :class:`JebDecompilation` with run evidence.

    Raises:
        AnalysisError: When JEB is not installed (typed reason ending with
            :data:`COMMERCIAL_NOTE`), the file is missing or is not a DEX/APK,
            a filter or the timeout is invalid, the run fails or times out, or
            the output is not the marker contract this lane parses.
    """
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"DEX/APK file not found: {target}")
    suffix = target.suffix.lower()
    if suffix not in DEX_SUFFIXES:
        raise AnalysisError(
            f"JEB decompiles DEX/APK classes, not {suffix or 'extensionless'} files; "
            f"expected one of {', '.join(DEX_SUFFIXES)}"
        )
    wanted_class = _check_filter("class_name", class_name)
    wanted_method = _check_filter("method", method)
    timeout = _check_timeout(timeout_s)
    export_dir: Path | None = None
    if out_dir is not None:
        if not isinstance(out_dir, (str, Path)):
            raise AnalysisError(
                f"out_dir must be a str, Path or None, got {type(out_dir).__name__}"
            )
        export_dir = Path(out_dir)
        if export_dir.exists() and not export_dir.is_dir():
            raise AnalysisError(f"out_dir {export_dir} exists and is not a directory")
    capability = probe_jeb(which=which, runner=runner, environ=environ)
    executable = capability.executable
    if not capability.available or executable is None:
        raise AnalysisError(f"JEB headless decompilation is unavailable: {capability.reason}")

    temporary: Path | None = None
    try:
        if export_dir is None:
            temporary = Path(tempfile.mkdtemp(prefix="codevanta-jeb-"))
            script_dir = temporary
        else:
            script_dir = export_dir
        script = _write_script(script_dir)
        command = (executable, "--script", str(script), "--", str(target))
        execute = runner if runner is not None else subprocess.run
        try:
            outcome = execute(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AnalysisError(
                f"JEB exceeded its timeout of {timeout:g}s and was terminated"
            ) from exc
        except FileNotFoundError as exc:
            raise AnalysisError(
                f"the JEB launcher '{executable}' vanished between the probe and the run"
            ) from exc
        except OSError as exc:
            raise AnalysisError(
                f"the JEB launcher '{executable}' could not run: {exc}"
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
        transcript = stdout if isinstance(stdout, str) else ""
        if returncode != 0:
            raise AnalysisError(
                f"JEB exited with code {returncode}: "
                f"{_tail(str(stderr_text)) or 'no stderr output'}"
            )
        if not transcript.strip():
            raise AnalysisError(
                "JEB produced no headless output; the export script printed nothing -- "
                "check the license and that the target is a valid DEX/APK"
            )
        lines = transcript.splitlines()
        capped = "\n".join(lines[:MAX_LINES])
        parsed = parse_jeb_output(
            capped,
            target=str(target),
            class_name=wanted_class,
            method=wanted_method,
        )
        warnings = list(parsed.warnings)
        truncated = parsed.truncated or len(lines) > MAX_LINES
        if len(lines) > MAX_LINES:
            _note(
                warnings,
                f"headless output capped at {MAX_LINES} lines; further lines dropped",
            )
        return replace(
            parsed,
            truncated=truncated,
            warnings=tuple(warnings),
            evidence=Evidence(
                source=EVIDENCE_SOURCE,
                method=EVIDENCE_METHOD,
                confidence=Confidence.HIGH,
                detail=(
                    f"{len(parsed.classes)} class(es) and {parsed.method_count} method(s) "
                    f"exported from {target.name} through JEB headless script mode "
                    f"(timeout {timeout:g}s)"
                ),
                extra={
                    "executable": executable,
                    "script": str(script),
                    "timeout_seconds": timeout,
                },
            ),
        )
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)

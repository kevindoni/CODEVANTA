"""Shared bridge framework: probe external analysis tools, report capability.

CODEVANTA's own analyzers are pure Python and always available; a *depth
bridge* adds a third-party tool's interpretation on top when that tool happens
to be installed. This module is the single place that answers "which bridges
could this machine use?": :func:`probe_bridge` answers for one tool,
:func:`bridges_report` answers for all of them in a deterministic order.

Every probe is the same two-step skip-gate the adb/sigrok lanes established:

1. ``shutil.which`` for the executable (``z3`` is a package import probe);
2. one bounded ``--version`` call (5 second timeout) whose first semantic
   version-looking token becomes :attr:`BridgeCapability.version`.

Two probes delegate to the lane that owns the tool's real probe, so the report
can never drift from the wrapper: ``jeb`` asks
:func:`codevanta.analysis.jeb_bridge.probe_jeb` (commercial tool, ``JEB_HOME``
aware, tolerant of JEB's missing ``--version`` banner) and ``hopper`` asks
:func:`codevanta.analysis.hopper_bridge.probe_hopper` (macOS-only GUI bundle
probe -- available means "installed", never "headless-capable").

Nothing here ever raises for a missing or broken tool: absence comes back as
``available=False`` with a human-readable ``reason``. Only an unknown bridge
*name* raises the typed :class:`~codevanta.core.report.AnalysisError`, because
that is a caller bug rather than a machine property.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from codevanta.analysis.hopper_bridge import probe_hopper as _probe_hopper_lane
from codevanta.analysis.jeb_bridge import probe_jeb as _probe_jeb_lane
from codevanta.core.report import AnalysisError

__all__ = [
    "KNOWN_BRIDGES",
    "PROBE_TIMEOUT",
    "BridgeCapability",
    "bridges_report",
    "probe_bridge",
]

#: Wall-clock budget for one bounded ``--version`` probe call, in seconds.
PROBE_TIMEOUT = 5.0

#: Evidence ``source`` id shared by every probe report in this lane.
EVIDENCE_SOURCE = "bridge.probe"

#: Deterministic report order; ``jeb``/``hopper`` are delegated probes and ``z3``
#: is last because it is the only import probe.
KNOWN_BRIDGES: tuple[str, ...] = (
    "binwalk",
    "unblob",
    "tshark",
    "wabt",
    "objdump",
    "sigrok-cli",
    "adb",
    "gdb",
    "jeb",
    "hopper",
    "z3",
)

#: Install hints surfaced in ``reason`` when a bridge is unavailable.
_INSTALL_HINTS: dict[str, str] = {
    "binwalk": "pip install binwalk (or https://github.com/ReFirmLabs/binwalk)",
    "unblob": "pip install unblob (https://unblob.org)",
    "tshark": "install Wireshark/tshark (https://www.wireshark.org)",
    "wabt": "install the WebAssembly Binary Toolkit (https://github.com/WebAssembly/wabt/releases)",
    "objdump": "install GNU binutils (https://ftp.gnu.org/gnu/binutils/)",
    "sigrok-cli": "install sigrok-cli (https://sigrok.org/wiki/Downloads)",
    "adb": "install Android platform-tools (https://developer.android.com/tools/releases/platform-tools)",
    "gdb": "install gdb (https://www.gnu.org/software/gdb/)",
    "jeb": "JEB is commercial; install it and set JEB_HOME",
    "hopper": "install the Hopper GUI on macOS (https://www.hopperapp.com)",
    "z3": "pip install z3-solver",
}

#: Any ``major.minor`` / ``major.minor.patch`` token in a version banner.
_SEMVER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


class VersionRunner(Protocol):
    """The injectable stand-in for ``subprocess.run`` (offline tests)."""

    def __call__(self, command: tuple[str, ...], **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class _ProbeSpec:
    """How to probe one bridge: executables, version argv, banner parser."""

    name: str
    executables: tuple[str, ...]
    #: ``--version`` style argv; ``adb`` uses ``version``, sigrok uses ``-V``.
    version_args: tuple[str, ...]
    #: First lines searched for a version token (``tshark`` banners are long).
    scan_limit_lines: int = 3


_PROBE_SPECS: dict[str, _ProbeSpec] = {
    spec.name: spec
    for spec in (
        _ProbeSpec("binwalk", ("binwalk",), ("--version",)),
        _ProbeSpec("unblob", ("unblob",), ("--version",)),
        _ProbeSpec("tshark", ("tshark",), ("--version",), scan_limit_lines=1),
        _ProbeSpec("wabt", ("wasm-validate", "wasm-objdump"), ("--version",)),
        _ProbeSpec("objdump", ("objdump",), ("--version",)),
        _ProbeSpec("sigrok-cli", ("sigrok-cli",), ("-V",)),
        _ProbeSpec("adb", ("adb",), ("version",)),
        _ProbeSpec("gdb", ("gdb",), ("--version",)),
    )
}


@dataclass(frozen=True)
class BridgeCapability:
    """One external tool's availability on this machine.

    Attributes:
        tool: Bridge name, one of :data:`KNOWN_BRIDGES`.
        available: Whether the probe found a working tool.
        version: Parsed version string, ``None`` when unknown/unavailable.
        reason: Why the bridge is unavailable (install hint included); probe
            detail when available. ``None`` only after a clean probe.
    """

    tool: str
    available: bool
    version: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (the canonical payload for CLI/MCP consumers)."""
        return {
            "tool": self.tool,
            "available": self.available,
            "version": self.version,
            "reason": self.reason,
        }

def parse_version_banner(text: Any, *, scan_limit_lines: int = 3) -> str | None:
    """Return the first semantic version token in ``text``, ``None`` when none.

    Only the first ``scan_limit_lines`` lines are scanned, so late chatter in
    long banners (``tshark`` credits, ``gdb`` copyright) cannot smuggle in a
    wrong version. Anything that is not ``str`` raises the typed error.
    """
    if not isinstance(text, str):
        raise AnalysisError(f"version banner must be a string, got {type(text).__name__}")
    for line in text.splitlines()[:scan_limit_lines]:
        match = _SEMVER_RE.search(line)
        if match is not None:
            return match.group(1)
    return None


def _probe_z3() -> BridgeCapability:
    """Import-probe the optional ``z3`` package (no subprocess involved)."""
    found = importlib.util.find_spec("z3") is not None
    if not found:
        return BridgeCapability(
            tool="z3",
            available=False,
            reason=f"the z3 package is not importable; {_INSTALL_HINTS['z3']}",
        )
    version: str | None = None
    try:
        version = importlib.metadata.version("z3-solver")
    except importlib.metadata.PackageNotFoundError:
        version = None
    if version is None:
        return BridgeCapability(
            tool="z3",
            available=True,
            reason="z3 imports; distribution metadata did not name a version",
        )
    return BridgeCapability(tool="z3", available=True, version=version)


def _probe_jeb(which: Any, runner: VersionRunner | None) -> BridgeCapability:
    """Delegate to the JEB lane (commercial tool, ``JEB_HOME`` aware)."""
    capability = _probe_jeb_lane(which=which, runner=runner)
    return BridgeCapability(
        tool="jeb",
        available=capability.available,
        version=capability.version,
        reason=capability.reason,
    )


def _probe_hopper() -> BridgeCapability:
    """Delegate to the Hopper lane (macOS GUI bundle probe; no version exists)."""
    capability = _probe_hopper_lane()
    return BridgeCapability(
        tool="hopper",
        available=capability.available,
        version=None,
        reason=capability.reason,
    )


def _run_version_probe(
    spec: _ProbeSpec,
    paths: list[str],
    *,
    runner: VersionRunner | None = None,
) -> tuple[str | None, str | None]:
    """Run one bounded version call; return ``(version, failure_reason)``.

    Exactly one of the two is non-``None``. Every failure mode -- timeout,
    FileNotFoundError, OSError, nonzero exit, unparseable banner -- degrades
    into the reason string; the probe never raises for tool behaviour.
    """
    execute = runner if runner is not None else subprocess.run
    command = (paths[0], *spec.version_args)
    try:
        outcome = execute(command, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, (
            f"'{spec.name} {' '.join(spec.version_args)}' timed out "
            f"after {PROBE_TIMEOUT:g}s"
        )
    except FileNotFoundError:
        return None, f"'{paths[0]}' vanished between the PATH probe and the version call"
    except OSError as exc:
        return None, f"'{paths[0]}' could not be executed: {exc}"
    returncode = getattr(outcome, "returncode", None)
    stdout = getattr(outcome, "stdout", None)
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    banner = stdout if isinstance(stdout, str) else ""
    if isinstance(returncode, int) and returncode != 0:
        return None, f"'{spec.name}' exited with code {returncode}"
    version = parse_version_banner(banner, scan_limit_lines=spec.scan_limit_lines)
    if version is None:
        return None, f"'{spec.name}' printed no parseable version banner"
    return version, None
def probe_bridge(
    name: str,
    *,
    which: Any = None,
    runner: VersionRunner | None = None,
) -> BridgeCapability:
    """Probe one bridge by name and return its capability record.

    Args:
        name: One of :data:`KNOWN_BRIDGES`.
        which: Injectable ``shutil.which`` stand-in (offline tests).
        runner: Injectable ``subprocess.run`` stand-in (offline tests).

    Returns:
        The capability record. Unavailability is a record with
        ``available=False`` and a ``reason`` naming the missing executable
        plus the install hint -- never an exception.

    Raises:
        AnalysisError: When ``name`` is not a known bridge (caller bug).
    """
    if not isinstance(name, str):
        raise AnalysisError(f"bridge name must be a string, got {type(name).__name__}")
    key = name.strip()
    if key != name:
        raise AnalysisError(f"bridge name {name!r} must not have surrounding whitespace")
    if key == "z3":
        return _probe_z3()
    if key == "hopper":
        return _probe_hopper()
    if key == "jeb":
        return _probe_jeb(which, runner)
    spec = _PROBE_SPECS.get(key)
    if spec is None:
        raise AnalysisError(
            f"unknown bridge {name!r}; known bridges: {', '.join(KNOWN_BRIDGES)}"
        )
    which_fn = which if which is not None else shutil.which
    paths: list[str] = []
    for executable in spec.executables:
        found = which_fn(executable)
        if not found:
            return BridgeCapability(
                tool=key,
                available=False,
                reason=f"'{executable}' is not on PATH; install it with {_INSTALL_HINTS[key]}",
            )
        paths.append(found)
    version, failure = _run_version_probe(spec, paths, runner=runner)
    if failure is not None:
        return BridgeCapability(tool=key, available=False, version=None, reason=failure)
    return BridgeCapability(tool=key, available=True, version=version, reason=None)


def bridges_report(
    *,
    which: Any = None,
    runner: VersionRunner | None = None,
) -> list[BridgeCapability]:
    """Probe every known bridge in :data:`KNOWN_BRIDGES` order (deterministic).

    The report is honest by construction: on this machine it lists whatever is
    really installed, and on a slim machine it lists typed unavailability
    reasons instead of failing. Every entry is JSON-safe via ``to_dict()``.
    """
    return [probe_bridge(name, which=which, runner=runner) for name in KNOWN_BRIDGES]


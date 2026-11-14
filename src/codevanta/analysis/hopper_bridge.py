"""Hopper bridge: a probe, and an honest ceiling instead of a fake wrapper.

Hopper is a **macOS GUI application**. It has no supported headless
decompilation interface: there is no documented batch/CLI entry point that
exports pseudocode for a binary, and everything useful happens inside the GUI
(``File > Produce Pseudo-code``). This module therefore does exactly two things
and refuses to do a third:

* :func:`probe_hopper` reports whether Hopper is installed -- ``sys.platform``
  must be ``darwin`` *and* a ``/Applications/Hopper Disassembler*.app`` bundle
  must exist -- returning a typed, JSON-safe :class:`HopperCapability`;
* :func:`hopper_export_instructions` raises the typed
  :class:`~codevanta.core.report.AnalysisError` that tells the user how to get
  pseudocode anyway: export it from the GUI, or use ``--provider ghidra``.

Contract (please keep it this way)
----------------------------------
There is deliberately **no** ``hopper_decompile()``, no subprocess call and no
"headless" claim in this module. A wrapper that shelled out to the Hopper
executable would either hang on a GUI prompt or silently produce nothing, which
is exactly the kind of dishonesty the rest of the bridge lane avoids. The
provider router (:mod:`codevanta.analysis.decompile_router`) lists ``hopper`` in
its availability report for completeness but never nominates it for routing,
and the MCP/CLI surfaces document it as GUI-export-only.
"""

from __future__ import annotations

import glob
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "APP_GLOB",
    "EVIDENCE_SOURCE",
    "HEADLESS_MESSAGE",
    "MACOS_ONLY",
    "HopperCapability",
    "hopper_export_instructions",
    "probe_hopper",
]

#: Glob for the Hopper application bundle's executable directory.
APP_GLOB = "/Applications/Hopper Disassembler*.app/Contents/MacOS/*"

#: The macOS-only note every capability reason carries.
MACOS_ONLY = "Hopper is a macOS-only GUI application"

#: The typed ceiling message: what Hopper cannot do headlessly, and the way out.
HEADLESS_MESSAGE = (
    "Hopper headless decompilation is not scriptable; export pseudocode from the GUI "
    "or use --provider ghidra"
)

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "decompile.hopper"

#: Injectable stand-in for :func:`glob.glob` (offline tests).
Finder = Callable[[str], Sequence[str]]


@dataclass(frozen=True)
class HopperCapability:
    """Whether the Hopper GUI is installed on this (macOS) machine.

    Attributes:
        available: True only on macOS with a Hopper bundle present.
        app_path: Absolute path of the bundle's executable, ``None`` otherwise.
        reason: Always a non-empty explanation; it names the macOS-only
            constraint and, when the bundle exists, repeats the GUI-export
            ceiling.
    """

    available: bool
    app_path: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (the canonical payload for CLI/MCP consumers)."""
        return {
            "available": self.available,
            "app_path": self.app_path,
            "reason": self.reason,
        }

    def to_evidence(self) -> Evidence:
        """Evidence record for this probe (``decompile.hopper``)."""
        return Evidence(
            source=EVIDENCE_SOURCE,
            method="gui_bundle_probe",
            confidence=Confidence.HIGH,
            detail=self.reason or "Hopper GUI probe",
            extra={"app_path": self.app_path, "macos_only": True},
        )


def probe_hopper(
    *,
    platform: str | None = None,
    finder: Finder | None = None,
) -> HopperCapability:
    """Probe for the Hopper GUI bundle; never raises, never launches anything.

    Args:
        platform: Injectable ``sys.platform`` stand-in (offline tests).
        finder: Injectable :func:`glob.glob` stand-in (offline tests).

    Returns:
        The capability record. Absence is ``available=False`` plus a reason that
        always names the macOS-only constraint; on macOS with the bundle
        installed the reason repeats the GUI-export ceiling, because
        ``available=True`` here still does not mean headless decompilation.
    """
    current = sys.platform if platform is None else platform
    if current != "darwin":
        return HopperCapability(
            available=False,
            app_path=None,
            reason=(
                f"{MACOS_ONLY}; this host is {current!r}, so Hopper cannot run here -- "
                f"export pseudocode on macOS, or use --provider ghidra"
            ),
        )
    locate = finder if finder is not None else glob.glob
    matches = sorted(str(match) for match in locate(APP_GLOB))
    if not matches:
        return HopperCapability(
            available=False,
            app_path=None,
            reason=(
                f"{MACOS_ONLY}; no {APP_GLOB} bundle was found -- install Hopper and "
                f"export pseudocode from the GUI, or use --provider ghidra"
            ),
        )
    return HopperCapability(
        available=True,
        app_path=matches[0],
        reason=f"Hopper GUI at {matches[0]} ({MACOS_ONLY}); {HEADLESS_MESSAGE}",
    )


def hopper_export_instructions() -> NoReturn:
    """Raise the typed Hopper ceiling: headless decompilation is not scriptable.

    Raises:
        AnalysisError: Always, with :data:`HEADLESS_MESSAGE` -- Hopper's
            pseudocode can only be exported from the GUI, so there is no
            headless call to make.
    """
    raise AnalysisError(HEADLESS_MESSAGE)

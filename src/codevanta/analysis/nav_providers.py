"""External GUI provider probes: what live-GUI bridging *could* attach to.

CODEVANTA's own navigation (:mod:`codevanta.analysis.nav`) is provider-neutral
and works offline, with or without any disassembler GUI installed. This module
answers a different question: which external reverse-engineering GUIs are
present on this machine, so a future live bridge knows what it *could* talk
to. Every probe is a pure, offline presence check -- it never launches the
GUI, never opens a socket and never crashes: a surprising environment yields
an "unavailable" capability with the reason, not an exception.

The three probes cover the macOS-only Hopper Disassembler app bundle, the
Qt-based Cutter (``cutter`` on ``PATH``) and Ghidra headless (either the
``GHIDRA_INSTALL_DIR`` environment variable pointing at an installation with
``analyzeHeadless``, or ``analyzeHeadless[.bat]`` itself on ``PATH``).
"""

from __future__ import annotations

import glob
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Any

__all__ = [
    "GHIDRA_ENV_VAR",
    "TypedProviderCapability",
    "probe_cutter",
    "probe_ghidra",
    "probe_hopper",
    "providers_report",
]

#: Environment variable that points at a Ghidra installation directory.
GHIDRA_ENV_VAR = "GHIDRA_INSTALL_DIR"


@dataclass(frozen=True)
class TypedProviderCapability:
    """One provider's presence, as a typed and JSON-safe capability report."""

    name: str
    available: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the capability for CLI ``--json`` and MCP payloads."""
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
        }


def probe_hopper() -> TypedProviderCapability:
    """Report whether the Hopper Disassembler app bundle is installed.

    Hopper ships as a macOS application bundle, so the probe first requires
    ``sys.platform == "darwin"`` and then looks for ``/Applications/Hopper*.app``.
    """
    if sys.platform != "darwin":
        return TypedProviderCapability(
            name="hopper",
            available=False,
            reason=(
                f"Hopper Disassembler is a macOS application bundle; this platform "
                f"is {sys.platform}"
            ),
        )
    bundles = sorted(glob.glob("/Applications/Hopper*.app"))
    if not bundles:
        return TypedProviderCapability(
            name="hopper",
            available=False,
            reason="no Hopper*.app bundle found in /Applications",
        )
    return TypedProviderCapability(
        name="hopper",
        available=True,
        reason=f"found app bundle {bundles[0]}",
    )


def probe_cutter() -> TypedProviderCapability:
    """Report whether Cutter is reachable as ``cutter`` on ``PATH``."""
    binary = shutil.which("cutter")
    if binary is None:
        return TypedProviderCapability(
            name="cutter",
            available=False,
            reason="cutter is not on PATH",
        )
    return TypedProviderCapability(
        name="cutter",
        available=True,
        reason=f"cutter on PATH at {binary}",
    )


def _ghidra_headless_script() -> str:
    """Name of the headless driver script inside a Ghidra installation."""
    return "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def probe_ghidra() -> TypedProviderCapability:
    """Report whether Ghidra headless is discoverable.

    ``GHIDRA_INSTALL_DIR`` wins when it points at a directory that actually
    contains the ``analyzeHeadless`` script; otherwise the probe looks for
    ``analyzeHeadless`` (``analyzeHeadless.bat`` on Windows) on ``PATH``.
    """
    script = _ghidra_headless_script()
    install_dir = os.environ.get(GHIDRA_ENV_VAR)
    if install_dir and install_dir.strip():
        candidate = os.path.join(install_dir.strip(), script)
        if os.path.isfile(candidate):
            return TypedProviderCapability(
                name="ghidra",
                available=True,
                reason=f"{GHIDRA_ENV_VAR} installation with {script} at {candidate}",
            )
    on_path = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
    if on_path is not None:
        return TypedProviderCapability(
            name="ghidra",
            available=True,
            reason=f"analyzeHeadless on PATH at {on_path}",
        )
    if install_dir and install_dir.strip():
        return TypedProviderCapability(
            name="ghidra",
            available=False,
            reason=(
                f"{GHIDRA_ENV_VAR} points at {install_dir.strip()} but no {script} "
                f"was found there and none is on PATH"
            ),
        )
    return TypedProviderCapability(
        name="ghidra",
        available=False,
        reason=(
            f"{GHIDRA_ENV_VAR} is not set and analyzeHeadless is not on PATH"
        ),
    )


def providers_report() -> list[TypedProviderCapability]:
    """Probe every known provider and return the capability reports.

    Each probe runs inside its own guard: an unexpected environment failure
    becomes an ``available=False`` capability whose reason says the probe
    itself failed, so the report can never raise.
    """
    probes = (
        ("hopper", probe_hopper),
        ("cutter", probe_cutter),
        ("ghidra", probe_ghidra),
    )
    report: list[TypedProviderCapability] = []
    for name, probe in probes:
        try:
            report.append(probe())
        except Exception as exc:  # noqa: BLE001 - the probe boundary is the point
            report.append(
                TypedProviderCapability(
                    name=name,
                    available=False,
                    reason=f"probe failed: {exc!r}",
                )
            )
    return report

"""Provider routing for the decompile lane: one typed answer to "who renders this?".

CODEVANTA can decompile with four address-level or class-level providers, plus
one GUI application it can only *probe*. This module is the single place that
decides, deterministically and honestly, which provider the ``auto`` policy
picks:

===========  ==============  ==================================================
 provider      kind            nominated when
===========  ==============  ==================================================
 ``jeb``       ``dex``         the target is ``.dex``/``.apk`` **and** JEB is
                               installed (class-level export, see
                               :mod:`codevanta.analysis.jeb_bridge`)
 ``ghidra``    ``address``     ``pyghidra`` imports and ``GHIDRA_INSTALL_DIR``
                               points at an installation
 ``angr``      ``address``     ``angr`` imports
 ``native``    ``address``     always -- the floor never drops
 ``hopper``    ``gui``         never: it is macOS-GUI-only and has no headless
                               interface (:mod:`codevanta.analysis.hopper_bridge`)
===========  ==============  ==================================================

Two typed records come out of here, both frozen, JSON-safe and evidenced under
the ``decompile.route`` source id:

* :class:`ProviderReport` -- what this machine actually has (``codevanta
  providers`` prints it, ``codevanta_providers`` returns it over MCP);
* :class:`ProviderRoute` -- the decision for one target: the chosen
  ``provider``, the ``address_backend`` an address-based render must use, the
  ``skipped`` providers with their reasons, and ``notes`` for the structural
  remarks (a non-DEX target means JEB was not even considered).

Every probe is injectable (``jeb=``, ``hopper=``, ``backends=``), so the whole
policy is testable offline with monkeypatched probes and no tool installed.
Nothing here ever raises for a missing tool: absence is a typed reason. Only a
non-path ``path`` or an unknown provider name raises
:class:`~codevanta.core.report.AnalysisError`, because those are caller bugs.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.decompilers import available_backends
from codevanta.analysis.hopper_bridge import HopperCapability, probe_hopper
from codevanta.analysis.jeb_bridge import DEX_SUFFIXES, JebCapability, probe_jeb
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "ADDRESS_PROVIDERS",
    "AUTO",
    "EVIDENCE_SOURCE",
    "PROVIDER_KINDS",
    "PROVIDER_ORDER",
    "PROVIDERS",
    "REPORT_ORDER",
    "ProviderReport",
    "ProviderRoute",
    "ProviderStatus",
    "provider_report",
    "route_provider",
]

#: The policy name that triggers routing.
AUTO = "auto"

#: Routing order for ``auto``: JEB first (DEX/APK only), then the address backends.
PROVIDER_ORDER: tuple[str, ...] = ("jeb", "ghidra", "angr", "native")

#: Providers that can render one function at an address, best first.
ADDRESS_PROVIDERS: tuple[str, ...] = ("ghidra", "angr", "native")

#: Deterministic report order: routing candidates, then the GUI-only probe.
REPORT_ORDER: tuple[str, ...] = (*PROVIDER_ORDER, "hopper")

#: Every name a caller may pass as a provider, ``auto`` included.
PROVIDERS: tuple[str, ...] = (AUTO, *REPORT_ORDER)

#: What each provider can consume.
PROVIDER_KINDS: dict[str, str] = {
    "jeb": "dex",
    "ghidra": "address",
    "angr": "address",
    "native": "address",
    "hopper": "gui",
}

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "decompile.route"

#: Probe stand-ins (module attributes, so tests can monkeypatch them).
JebProbe = Callable[[], JebCapability]
HopperProbe = Callable[[], HopperCapability]


@dataclass(frozen=True)
class ProviderStatus:
    """One provider's availability on this machine.

    Attributes:
        name: One of :data:`REPORT_ORDER`.
        available: Whether the provider can run here.
        kind: ``"address"`` (renders one function), ``"dex"`` (renders classes)
            or ``"gui"`` (GUI-only, never routable).
        version: Parsed version, ``None`` when the probe could not find one.
        reason: Why it is unavailable, or what it can do when available.
    """

    name: str
    available: bool
    kind: str
    version: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view (the canonical payload for CLI/MCP consumers)."""
        return {
            "name": self.name,
            "available": self.available,
            "kind": self.kind,
            "version": self.version,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ProviderReport:
    """The typed availability report over every decompiler provider."""

    providers: tuple[ProviderStatus, ...] = ()

    @property
    def available_count(self) -> int:
        """How many providers can run on this machine (``native`` makes it >= 1)."""
        return sum(1 for status in self.providers if status.available)

    def status(self, name: str) -> ProviderStatus:
        """Return one provider's status; an unknown name is a caller bug."""
        for status in self.providers:
            if status.name == name:
                return status
        raise AnalysisError(
            f"unknown decompiler provider {name!r}; known providers: {', '.join(REPORT_ORDER)}"
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view of the whole report, with counts."""
        return {
            "providers": [status.to_dict() for status in self.providers],
            "count": len(self.providers),
            "available": self.available_count,
        }

    def to_evidence(self) -> Evidence:
        """Evidence record for this report (``decompile.route``)."""
        return Evidence(
            source=EVIDENCE_SOURCE,
            method="provider_probe",
            confidence=Confidence.HIGH,
            detail=(
                f"{self.available_count}/{len(self.providers)} decompiler provider(s) "
                "available on this machine; native always runs"
            ),
            extra={
                "available": [
                    status.name for status in self.providers if status.available
                ]
            },
        )


@dataclass(frozen=True)
class ProviderRoute:
    """The routing decision for one target.

    Attributes:
        target: The path the decision was made for (as given).
        suffix: Lower-cased target suffix (``""`` when there is none).
        provider: The provider ``auto`` picked, first available in
            :data:`PROVIDER_ORDER` with JEB eligible only for DEX/APK.
        address_backend: The provider an address-based render must use
            (``jeb`` renders classes, never addresses).
        skipped: ``(provider, reason)`` for every unavailable provider.
        notes: Structural remarks, e.g. that a non-DEX target rules JEB out.
        reason: One-line explanation of the choice.
    """

    target: str
    suffix: str
    provider: str
    address_backend: str
    skipped: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    reason: str = ""

    @property
    def dex_target(self) -> bool:
        """Whether the target is a DEX/APK, i.e. whether JEB was eligible."""
        return self.suffix in DEX_SUFFIXES

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view of the decision."""
        return {
            "target": self.target,
            "suffix": self.suffix,
            "provider": self.provider,
            "address_backend": self.address_backend,
            "dex_target": self.dex_target,
            "skipped": [
                {"provider": name, "reason": reason} for name, reason in self.skipped
            ],
            "notes": list(self.notes),
            "reason": self.reason,
        }

    def to_evidence(self) -> Evidence:
        """Evidence record for this decision (``decompile.route``)."""
        return Evidence(
            source=EVIDENCE_SOURCE,
            method="auto_route",
            confidence=Confidence.HIGH,
            detail=self.reason or f"auto routed {self.target} to {self.provider}",
            extra={
                "provider": self.provider,
                "address_backend": self.address_backend,
                "skipped": [name for name, _ in self.skipped],
            },
        )



def provider_report(
    *,
    jeb: JebProbe | None = None,
    hopper: HopperProbe | None = None,
    backends: BackendsProbe | None = None,
) -> ProviderReport:
    """Probe every decompiler provider and return the typed report.

    Args:
        jeb: Injectable JEB probe (defaults to
            :func:`codevanta.analysis.jeb_bridge.probe_jeb`).
        hopper: Injectable Hopper probe (defaults to
            :func:`codevanta.analysis.hopper_bridge.probe_hopper`).
        backends: Injectable address-backend probe returning
            :class:`~codevanta.analysis.decompilers.BackendAvailability`
            records (defaults to
            :func:`~codevanta.analysis.decompilers.available_backends`).

    Returns:
        The report in :data:`REPORT_ORDER`; ``native`` is always available
        because it is pure Python and has no dependency to probe.
    """
    jeb_probe = jeb if jeb is not None else probe_jeb
    hopper_probe = hopper if hopper is not None else probe_hopper
    backend_probe = backends if backends is not None else available_backends
    jeb_capability = jeb_probe()
    hopper_capability = hopper_probe()
    reported = {str(getattr(item, "name", "")): item for item in backend_probe()}
    statuses: list[ProviderStatus] = [
        ProviderStatus(
            name="jeb",
            available=bool(jeb_capability.available),
            kind=PROVIDER_KINDS["jeb"],
            version=jeb_capability.version,
            reason=jeb_capability.reason,
        )
    ]
    for name in ADDRESS_PROVIDERS:
        if name == "native":
            statuses.append(
                ProviderStatus(
                    name=name,
                    available=True,
                    kind=PROVIDER_KINDS[name],
                    version=None,
                    reason="the built-in heuristic renderer needs no dependency",
                )
            )
            continue
        found = reported.get(name)
        if found is None:
            statuses.append(
                ProviderStatus(
                    name=name,
                    available=False,
                    kind=PROVIDER_KINDS[name],
                    version=None,
                    reason="the decompiler registry did not report this backend",
                )
            )
            continue
        statuses.append(
            ProviderStatus(
                name=name,
                available=bool(getattr(found, "available", False)),
                kind=PROVIDER_KINDS[name],
                version=None,
                reason=str(getattr(found, "reason", "") or ""),
            )
        )
    statuses.append(
        ProviderStatus(
            name="hopper",
            available=bool(hopper_capability.available),
            kind=PROVIDER_KINDS["hopper"],
            version=None,
            reason=hopper_capability.reason,
        )
    )
    return ProviderReport(providers=tuple(statuses))


def route_provider(
    path: str | Path,
    *,
    jeb: JebProbe | None = None,
    hopper: HopperProbe | None = None,
    backends: BackendsProbe | None = None,
    report: ProviderReport | None = None,
) -> ProviderRoute:
    """Decide which provider ``auto`` uses for ``path``.

    The policy is :data:`PROVIDER_ORDER` with one structural rule: ``jeb`` is
    only eligible when the target suffix is in
    :data:`~codevanta.analysis.jeb_bridge.DEX_SUFFIXES`. ``hopper`` is never a
    candidate (GUI-only), and ``native`` is the floor, so a provider is always
    chosen.

    Args:
        path: The target being decompiled; only its suffix matters.
        jeb: Injectable JEB probe.
        hopper: Injectable Hopper probe.
        backends: Injectable address-backend probe.
        report: A pre-computed report (skips probing entirely).

    Returns:
        The typed :class:`ProviderRoute` with reasons for every skip.

    Raises:
        AnalysisError: If ``path`` is not a ``str``/``Path``.
    """
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    suffix = target.suffix.lower()
    dex_target = suffix in DEX_SUFFIXES
    resolved = (
        report
        if report is not None
        else provider_report(jeb=jeb, hopper=hopper, backends=backends)
    )
    statuses = {status.name: status for status in resolved.providers}
    notes: list[str] = []
    chosen: str | None = None
    for name in PROVIDER_ORDER:
        if name == "jeb" and not dex_target:
            notes.append(
                f"target {suffix or 'without a suffix'} is not "
                f"{'/'.join(DEX_SUFFIXES)}, so jeb was not considered"
            )
            continue
        status = statuses[name]
        if status.available:
            chosen = name
            break
    provider = chosen if chosen is not None else "native"
    address_backend = next(
        (
            name
            for name in ADDRESS_PROVIDERS
            if statuses.get(name) is not None and statuses[name].available
        ),
        "native",
    )
    skipped = tuple(
        (name, statuses[name].reason or "unavailable")
        for name in PROVIDER_ORDER
        if name != provider and not statuses[name].available
    )
    if provider == "jeb":
        reason = (
            f"auto selected jeb for the {suffix} target (class-level export); "
            f"{address_backend} is the address-level renderer"
        )
    elif provider == "native":
        reason = (
            "auto fell back to the built-in native renderer; no external decompiler "
            "is installed for this target"
        )
    else:
        reason = f"auto selected {provider}, the first available provider for this target"
    return ProviderRoute(
        target=str(target),
        suffix=suffix,
        provider=provider,
        address_backend=address_backend,
        skipped=skipped,
        notes=tuple(notes),
        reason=reason,
    )

BackendsProbe = Callable[[], Sequence[Any]]

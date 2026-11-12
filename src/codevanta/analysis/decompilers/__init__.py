"""Pluggable decompiler providers: real decompilers when installed, native always.

CODEVANTA can render one function with three different providers, and picks one
without ever assuming a third-party package is present:

===========  ==============================================  =====================
 backend      runs when                                       output
===========  ==============================================  =====================
 ``ghidra``   ``pyghidra`` imports **and** ``GHIDRA_INSTALL_DIR``  Ghidra's C
              points at a Ghidra installation
 ``angr``     ``angr`` imports                                angr's C
 ``native``   always                                           heuristic pseudo-C
===========  ==============================================  =====================

Only the last one is a CODEVANTA dependency: the optional backends import their
heavy module lazily inside ``availability()`` / ``decompile()``, so this package
imports and answers :func:`available_backends` on a machine with neither angr nor
Ghidra, and never raises ``ImportError`` for a missing decompiler.

Public API
----------
* :class:`BackendAvailability` -- ``name``, ``available``, a non-empty ``reason``
  and the ``requires`` tuple for each backend, in the order ``ghidra``, ``angr``,
  ``native``.
* :class:`BackendResult` -- ``text``, ``backend``, ``language``, ``warnings`` and
  :class:`Evidence`, with a JSON-safe :meth:`BackendResult.to_dict`.
* :class:`DecompilerBackend` -- the protocol a provider implements.
* :func:`available_backends` -- probe all three, in order.
* :func:`get_backend` -- look one up by name; an unknown name raises
  :class:`AnalysisError` listing the supported set.
* :func:`decompile_function` -- the one entry point callers need.

Selection policy
----------------
``backend="native"`` always works. ``backend="angr"`` / ``"ghidra"`` are strict:
when the backend is unavailable the call raises :class:`AnalysisError` whose
message carries the probe's reason (install hint included) -- it never leaks an
``ImportError`` and never silently substitutes another provider.
``backend="auto"`` (the default) prefers the first available external backend in
the order ``ghidra``, ``angr`` and falls back to ``native``; whatever it chose,
the returned :class:`BackendResult` carries one warning per unavailable backend
naming that backend and its reason, so a fallback is never silent.

Budgets are validated once, here (:func:`codevanta.analysis.decompilers.base.
require_budget`), before any backend is touched: an out-of-range
``max_instructions`` / ``max_blocks`` raises regardless of the backend.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_BLOCKS,
    MAX_MAX_INSTRUCTIONS,
)
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError

from .angr_backend import AngrBackend
from .base import (
    LANGUAGE,
    BackendAvailability,
    BackendResult,
    DecompilerBackend,
    NativeBackend,
    require_budget,
)
from .ghidra_backend import GhidraBackend

__all__ = [
    "AUTO",
    "LANGUAGE",
    "AngrBackend",
    "BackendAvailability",
    "BackendResult",
    "DecompilerBackend",
    "GhidraBackend",
    "NativeBackend",
    "available_backends",
    "decompile_function",
    "get_backend",
    "require_budget",
    "supported_backends",
]

#: External backends in preference order for ``backend="auto"``.
_EXTERNAL_ORDER: tuple[str, ...] = ("ghidra", "angr")

#: Every supported backend, in report order (external ones first).
_BACKEND_ORDER: tuple[str, ...] = (*_EXTERNAL_ORDER, "native")

#: Backend instances by name; one shared stateless instance each.
_BACKENDS: dict[str, DecompilerBackend] = {
    backend.name: backend for backend in (GhidraBackend(), AngrBackend(), NativeBackend())
}

#: Name used by :func:`decompile_function` to mean "pick for me".
AUTO = "auto"


def supported_backends() -> tuple[str, ...]:
    """Return the supported backend names, in report order."""
    return _BACKEND_ORDER


def _probe(backend: DecompilerBackend) -> BackendAvailability:
    """Run one availability probe, turning a crash into an "unavailable" record."""
    try:
        return backend.availability()
    except Exception as exc:  # a broken optional dependency must never break discovery
        return BackendAvailability(
            name=backend.name,
            available=False,
            reason=f"the availability probe itself failed ({type(exc).__name__}: {exc})",
            requires=tuple(backend.requires),
        )


def available_backends() -> tuple[BackendAvailability, ...]:
    """Probe every backend without installing or launching anything.

    Returns:
        One record per supported backend, always in the order ``ghidra``, ``angr``,
        ``native``. Unavailable records always carry a non-empty reason.
    """
    return tuple(_probe(_BACKENDS[name]) for name in _BACKEND_ORDER)


def get_backend(name: str) -> DecompilerBackend:
    """Return the backend registered under ``name``.

    Args:
        name: ``ghidra``, ``angr`` or ``native``; matched case-insensitively and
            ignoring surrounding whitespace.

    Returns:
        The shared backend instance. Availability is *not* checked here; call
        :meth:`DecompilerBackend.availability` or use :func:`decompile_function`.

    Raises:
        AnalysisError: When the name is unknown; the message lists the supported set.
    """
    key = name.strip().lower() if isinstance(name, str) else ""
    backend = _BACKENDS.get(key)
    if backend is None:
        raise AnalysisError(
            f"unknown decompiler backend {name!r}; supported backends: {', '.join(_BACKEND_ORDER)}"
        )
    return backend


def _unavailable_message(availability: BackendAvailability) -> str:
    """Explain why a strictly requested backend cannot run."""
    return (
        f"decompiler backend {availability.name!r} is unavailable: {availability.reason}; "
        "use backend='auto' to fall back to another provider, or backend='native'"
    )


def decompile_function(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    backend: str = AUTO,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
) -> BackendResult:
    """Decompile one function with the requested backend.

    Args:
        path: Binary the function lives in (opened read-only; never executed).
        info: Loaded metadata for ``path``.
        address: Virtual address of the function.
        backend: ``"auto"`` (default), ``"native"``, ``"angr"`` or ``"ghidra"``.
        max_instructions: Instruction budget, validated against
            :data:`~codevanta.analysis.decompile.MAX_MAX_INSTRUCTIONS`.
        max_blocks: Block budget, validated against
            :data:`~codevanta.analysis.decompile.MAX_MAX_BLOCKS`.

    Returns:
        The :class:`BackendResult` of whichever backend produced the text.

    Raises:
        AnalysisError: On an unknown backend name, on an out-of-range budget, when
            a strictly requested backend is unavailable (the message carries the
            reason), or when the backend itself rejects the request. A missing
            optional dependency never surfaces as ``ImportError``.
    """
    instruction_budget = require_budget("max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS)
    block_budget = require_budget("max_blocks", max_blocks, MAX_MAX_BLOCKS)
    if not isinstance(backend, str):
        raise AnalysisError(f"backend must be a string, not {type(backend).__name__}")
    key = backend.strip().lower() or AUTO
    if key == AUTO:
        return _decompile_auto(path, info, address, instruction_budget, block_budget)
    chosen = get_backend(key)
    availability = _probe(chosen)
    if not availability.available:
        raise AnalysisError(_unavailable_message(availability))
    return chosen.decompile(
        path,
        info,
        address,
        max_instructions=instruction_budget,
        max_blocks=block_budget,
    )


def _decompile_auto(
    path: str | Path,
    info: BinaryInfo,
    address: int,
    max_instructions: int,
    max_blocks: int,
) -> BackendResult:
    """Pick the best available provider and record every fallback in ``warnings``."""
    probes = tuple(_probe(_BACKENDS[name]) for name in _EXTERNAL_ORDER)
    notes = [
        f"auto: backend {probe.name!r} was unavailable and skipped: {probe.reason}"
        for probe in probes
        if not probe.available
    ]
    for probe in probes:
        if not probe.available:
            continue
        try:
            result = _BACKENDS[probe.name].decompile(
                path,
                info,
                address,
                max_instructions=max_instructions,
                max_blocks=max_blocks,
            )
        except AnalysisError as exc:
            notes.append(f"auto: backend {probe.name!r} failed and was skipped: {exc}")
            continue
        return replace(result, warnings=(*notes, *result.warnings))

    result = _BACKENDS["native"].decompile(
        path,
        info,
        address,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    return replace(result, warnings=(*notes, *result.warnings))

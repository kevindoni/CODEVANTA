"""Backend-neutral primitives shared by every decompiler provider (phase 3).

The package :mod:`codevanta.analysis.decompilers` lets CODEVANTA use a *real*
decompiler when one happens to be installed and its own heuristic renderer
otherwise. This module holds the parts that must never depend on an optional
third-party package:

* :class:`BackendAvailability` -- the answer to "can this backend run here, and
  if not, why not". A probe never raises; a missing dependency becomes an
  ``available=False`` record with a human-readable :attr:`BackendAvailability.reason`.
* :class:`BackendResult` -- the backend-neutral rendering handed back to the CLI,
  the MCP server and the report: ``text``, which backend produced it, the source
  ``language``, the ``warnings`` collected on the way and the :class:`Evidence`
  that justifies it. :meth:`BackendResult.to_dict` is JSON-safe.
* :class:`DecompilerBackend` -- the structural protocol every provider
  implements (``name``, ``requires``, ``availability()``, ``decompile(...)``).
* :class:`NativeBackend` -- the fallback provider. It forwards to
  :func:`codevanta.analysis.decompile.decompile_function` and can therefore
  always answer, because that renderer only needs the required ``capstone``
  dependency and the loaded binary metadata.
* :func:`require_budget` -- the single validation path for
  ``max_instructions`` / ``max_blocks``, so every backend rejects the same
  out-of-range requests with the same :class:`AnalysisError` messages as the
  native renderer.

Heavy modules are imported lazily: this file imports only the standard library
plus in-project modules that are already required to run CODEVANTA, and the
optional backends (:mod:`codevanta.analysis.decompilers.angr_backend`,
:mod:`codevanta.analysis.decompilers.ghidra_backend`) import their dependency
inside ``availability()`` / ``decompile()`` only.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_BLOCKS,
    MAX_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompile import (
    decompile_function as render_pseudo_c,
)
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.models import Evidence

__all__ = [
    "BackendAvailability",
    "BackendResult",
    "DecompilerBackend",
    "NativeBackend",
    "require_budget",
]


#: Source language of every rendering this layer produces. All three backends
#: emit C (the native one emits *heuristic* pseudo-C), so the tag is shared.
@dataclass(frozen=True)
class BackendAvailability:
    """Whether one decompiler backend can run in this environment.

    Attributes:
        name: Backend identifier, one of ``ghidra``, ``angr`` or ``native``.
        available: ``True`` only when :meth:`DecompilerBackend.decompile` can be
            expected to run without installing anything else.
        reason: Human-readable explanation. Always non-empty: for an available
            backend it states what was detected, for an unavailable one it names
            the missing piece and, where possible, how to install it.
        requires: Packages or installations the backend needs, in the order they
            are probed. Empty for the built-in backend.
    """

    name: str
    available: bool
    reason: str
    requires: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the probe for the JSON report."""
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
            "requires": list(self.requires),
        }


@dataclass(frozen=True)
class BackendResult:
    """One decompilation rendered by a backend.

    Attributes:
        text: The rendering itself. Never empty: a backend that produced nothing
            still returns an explanatory ``/* ... */`` comment plus a warning.
        backend: Name of the backend that produced ``text`` (not the one that was
            requested, which matters for ``auto``).
        language: Source language tag of ``text``; always :data:`LANGUAGE` today.
        warnings: Everything the backend wants the caller to know: budget
            overruns it could not prevent, fallbacks, empty renderings.
        evidence: How the text was produced, including which backend and which
            budgets were in effect.
    """

    text: str
    backend: str
    language: str
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the rendering for the JSON report (JSON-safe values only)."""
        return {
            "text": self.text,
            "backend": self.backend,
            "language": self.language,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


@runtime_checkable
class DecompilerBackend(Protocol):
    """Structural interface every provider implements.

    The protocol is ``runtime_checkable`` so callers can assert that a registry
    entry really exposes ``name``, ``requires``, ``availability`` and
    ``decompile`` (attribute presence only; signatures are checked statically).

    Attributes:
        name: Short backend identifier used by :func:`get_backend`.
        requires: Hard requirements, reported verbatim by
            :class:`BackendAvailability`.
    """

    name: str
    requires: tuple[str, ...]

    def availability(self) -> BackendAvailability:
        """Probe the environment. Must never raise and never install anything."""
        ...

    def decompile(
        self,
        path: str | Path,
        info: BinaryInfo,
        address: int,
        max_instructions: int = ...,
        max_blocks: int = ...,
    ) -> BackendResult:
        """Render the function at ``address``.

        Raises:
            AnalysisError: When the backend is unavailable, when the request is
                out of range, or when the backend itself fails. Never raises
                ``ImportError`` for a missing optional dependency.
        """
        ...


LANGUAGE = "c"

#: Prefix of a warning line inside the native renderer's header comment block.
_HEADER_WARNING_PREFIX = " * warning: "

#: Prefix of the native renderer's "more warnings follow" summary line.
_HEADER_WARNING_OVERFLOW = "(+"


def require_budget(name: str, value: int, maximum: int) -> int:
    """Validate one budget argument against its hard limit.

    Mirrors the native renderer's validation so the provider layer and the
    renderer reject the same requests.

    Args:
        name: Argument name, used in the error message.
        value: Requested budget.
        maximum: Largest accepted value.

    Returns:
        ``value``, unchanged, for convenient inlining.

    Raises:
        AnalysisError: When ``value`` is not an ``int`` or is out of range.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an int, not {type(value).__name__}")
    if value < 1:
        raise AnalysisError(f"{name} must be >= 1, got {value}")
    if value > maximum:
        raise AnalysisError(f"{name} too large ({value}); limit is {maximum}")
    return value


def _header_warnings(body: str) -> tuple[str, ...]:
    """Lift the native renderer's ``warning:`` header lines out of the body."""
    warnings: list[str] = []
    for line in body.splitlines():
        if line == " */":
            break
        if not line.startswith(_HEADER_WARNING_PREFIX):
            continue
        text = line[len(_HEADER_WARNING_PREFIX) :].strip()
        if text and not text.startswith(_HEADER_WARNING_OVERFLOW):
            warnings.append(text)
    return tuple(warnings)


class NativeBackend:
    """The built-in heuristic pseudo-C renderer, always available.

    The rendering itself lives in :mod:`codevanta.analysis.decompile`; this
    provider only adapts its :class:`~codevanta.analysis.decompile.PseudoFunction`
    to the backend-neutral :class:`BackendResult` (``body`` becomes ``text``) and
    re-publishes the renderer's header warnings as structured warnings.
    """

    name: str = "native"
    requires: tuple[str, ...] = ()

    def availability(self) -> BackendAvailability:
        """Report the built-in renderer; it needs no optional dependency."""
        return BackendAvailability(
            name=self.name,
            available=True,
            reason=(
                "built-in mnemonic-level pseudo-C renderer; needs no optional "
                "dependency and always runs"
            ),
            requires=self.requires,
        )

    def decompile(
        self,
        path: str | Path,
        info: BinaryInfo,
        address: int,
        max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
    ) -> BackendResult:
        """Render ``address`` with the native heuristic renderer.

        Raises:
            AnalysisError: When the address is not executable code, when a budget
                is out of range, or when the region decodes to nothing.
        """
        instruction_budget = require_budget(
            "max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS
        )
        block_budget = require_budget("max_blocks", max_blocks, MAX_MAX_BLOCKS)
        rendered = render_pseudo_c(
            path,
            info,
            address,
            max_instructions=instruction_budget,
            max_blocks=block_budget,
        )
        evidence = replace(
            rendered.evidence,
            extra={
                **rendered.evidence.extra,
                "backend": self.name,
                "max_instructions": instruction_budget,
                "max_blocks": block_budget,
            },
        )
        return BackendResult(
            text=rendered.body,
            backend=self.name,
            language=LANGUAGE,
            warnings=_header_warnings(rendered.body),
            evidence=evidence,
        )

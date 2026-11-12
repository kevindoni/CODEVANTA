"""angr decompiler backend (optional dependency, imported lazily).

``angr`` ships a decompiler analysis on top of its CFG recovery, so it is the
cheapest way to get real pseudo-C without an external process. The package is
*not* a hard requirement of CODEVANTA: nothing here is imported until
:meth:`AngrBackend.availability` or :meth:`AngrBackend.decompile` runs, so
``import codevanta.analysis.decompilers`` never fails on a machine without angr.

Pipeline: ``angr.Project(path)`` (no shared libraries, no DWARF) -> ``CFGFast``
-> ``project.analyses.Decompiler(function, cfg=cfg.model)`` -> ``codegen.text``.

Budgeting: angr exposes no instruction or block budget on ``CFGFast`` and none on
``Decompiler``. The work is bounded *indirectly* -- the CFG starts from the one
requested address and indirect-jump resolution is disabled -- and the resulting
block count is checked against ``max_blocks`` afterwards, which can only be
reported as a warning. ``max_instructions`` cannot be enforced at all; both
budgets are recorded in the evidence so a reader can see what was asked for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_BLOCKS,
    MAX_MAX_INSTRUCTIONS,
)
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

from .base import (
    LANGUAGE,
    BackendAvailability,
    BackendResult,
    require_budget,
)

__all__ = ["AngrBackend", "INSTALL_HINT", "NAME"]

#: Backend identifier.
NAME = "angr"

#: What a user has to install for this backend to become available.
INSTALL_HINT = "pip install angr"

#: Evidence source label.
_SOURCE = "angr.decompiler"

#: Evidence method label.
_METHOD = "analyses.Decompiler"

#: Comment emitted when angr's decompiler produced no code.
_EMPTY_TEXT = "/* angr produced no pseudocode for 0x{address:x} */"


def _unavailable(availability: BackendAvailability) -> AnalysisError:
    """Build the error raised when a caller asked for an unavailable backend."""
    return AnalysisError(
        f"decompiler backend {availability.name!r} is unavailable: {availability.reason}; "
        "use backend='native' or backend='auto' instead"
    )


class AngrBackend:
    """Decompilation through angr's ``analyses.Decompiler``.

    Attributes:
        name: ``"angr"``.
        requires: ``("angr",)``.
    """

    name: str = NAME
    requires: tuple[str, ...] = ("angr",)

    def availability(self) -> BackendAvailability:
        """Probe ``import angr``; never raises, never installs anything."""
        try:
            import angr
        except ImportError as exc:
            return BackendAvailability(
                name=self.name,
                available=False,
                reason=(
                    f"the 'angr' package is not installed ({type(exc).__name__}: {exc}); "
                    f"install it with '{INSTALL_HINT}'"
                ),
                requires=self.requires,
            )
        except Exception as exc:  # a broken install must not break discovery
            return BackendAvailability(
                name=self.name,
                available=False,
                reason=(
                    f"importing 'angr' failed ({type(exc).__name__}: {exc}); "
                    f"reinstall it with '{INSTALL_HINT}'"
                ),
                requires=self.requires,
            )
        version = str(getattr(angr, "__version__", "unknown"))
        return BackendAvailability(
            name=self.name,
            available=True,
            reason=f"angr {version} is importable; CFGFast + analyses.Decompiler can run",
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
        """Decompile ``address`` with angr's decompiler analysis.

        Args:
            path: Binary to analyse (opened read-only by angr; never executed).
            info: Loaded metadata; angr loads the file itself, so only the path
                is used. Kept for a uniform backend signature.
            address: Virtual address of the function to decompile.
            max_instructions: Recorded and validated, but see the module
                docstring: angr cannot enforce an instruction budget.
            max_blocks: Checked against the recovered block count after the fact;
                an overrun becomes a warning, not an error.

        Returns:
            The rendering plus any warnings angr could not prevent.

        Raises:
            AnalysisError: When angr is unavailable, a budget is out of range,
                angr cannot load the file, or no function is recovered.
        """
        instruction_budget = require_budget(
            "max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS
        )
        block_budget = require_budget("max_blocks", max_blocks, MAX_MAX_BLOCKS)
        availability = self.availability()
        if not availability.available:
            raise _unavailable(availability)

        import angr

        warnings: list[str] = []
        try:
            project = angr.Project(str(path), auto_load_libs=False, load_debug_info=False)
        except Exception as exc:
            raise AnalysisError(
                f"angr could not load {str(path)!r}: {type(exc).__name__}: {exc}"
            ) from exc
        cfg = _recover_cfg(project, address)
        function = _lookup_function(cfg, address)
        try:
            analysis = project.analyses.Decompiler(function, cfg=cfg.model)
        except Exception as exc:
            raise AnalysisError(
                f"angr could not decompile 0x{address:x}: {type(exc).__name__}: {exc}"
            ) from exc

        text = _codegen_text(analysis)
        if not text.strip():
            warnings.append(
                f"angr returned no decompilation for 0x{address:x}: the analysis "
                "produced no codegen text, so the rendering is a placeholder comment"
            )
            text = _EMPTY_TEXT.format(address=address)

        block_count = len(list(getattr(function, "blocks", ()) or ()))
        if block_count > block_budget:
            warnings.append(
                f"angr decompiled {block_count} block(s), above max_blocks={block_budget}; "
                "angr exposes no block budget, so the text is complete rather than truncated"
            )

        version = _angr_version(angr)
        evidence = Evidence(
            source=_SOURCE,
            method=_METHOD,
            confidence=Confidence.MEDIUM,
            address=address,
            detail=(
                f"angr {version} decompiled the CFGFast function at 0x{address:x} "
                f"({block_count} block(s)); angr exposes no instruction or block budget, so "
                f"max_instructions={instruction_budget} could not be enforced and "
                f"max_blocks={block_budget} is checked afterwards only"
            ),
            extra={
                "backend": self.name,
                "angr_version": version,
                "max_instructions": instruction_budget,
                "max_blocks": block_budget,
                "block_count": block_count,
            },
        )
        return BackendResult(
            text=text,
            backend=self.name,
            language=LANGUAGE,
            warnings=tuple(warnings),
            evidence=evidence,
        )


def _angr_version(module: Any) -> str:
    """Return the installed angr version, or ``"unknown"``."""
    return str(getattr(module, "__version__", "unknown"))


def _recover_cfg(project: Any, address: int) -> Any:
    """Recover a CFG bounded to the one function start at ``address``.

    Indirect-jump resolution and data-reference discovery are switched off
    because both widen the scan without helping a single function; older angr
    builds reject some of these keywords, so the call falls back to the two
    options that do the actual bounding.
    """
    try:
        return project.analyses.CFGFast(
            starts=[address],
            function_starts=[address],
            resolve_indirect_jumps=False,
            data_references=False,
            normalize=True,
        )
    except TypeError:
        return project.analyses.CFGFast(starts=[address], function_starts=[address])


def _lookup_function(cfg: Any, address: int) -> Any:
    """Return the recovered function at ``address`` or raise :class:`AnalysisError`."""
    function = cfg.kb.functions.get(address)
    if function is None:
        raise AnalysisError(
            f"angr recovered no function at 0x{address:x}; the address may not be a "
            "function start or may be unreachable"
        )
    return function


def _codegen_text(analysis: Any) -> str:
    """Extract the pseudo-C text from a ``Decompiler`` analysis result."""
    codegen = getattr(analysis, "codegen", None)
    if codegen is None:
        return ""
    text = getattr(codegen, "text", "")
    return "" if text is None else str(text)

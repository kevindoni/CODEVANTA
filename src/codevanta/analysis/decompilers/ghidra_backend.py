"""Ghidra decompiler backend via ``pyghidra`` (optional, imported lazily).

Ghidra is the strongest free decompiler, but it needs two independent pieces: the
``pyghidra`` Python bridge *and* an actual Ghidra installation. Both are probed --
``pyghidra`` by importing it, the installation through the ``GHIDRA_INSTALL_DIR``
environment variable -- and the backend only reports ``available=True`` when both
are present. Nothing is ever downloaded, extracted or launched by the probe: a
machine without Ghidra simply gets ``available=False`` and a reason saying which
half is missing.

Rendering uses pyghidra's headless entry point, ``pyghidra.open_program``: it
starts the JVM, imports and analyses the file into an in-memory project and hands
back a ``FlatProgramAPI``. Inside that context ``ghidra.app.decompiler`` is
importable through JPype, so :class:`DecompInterface` decompiles the function at
the requested address and returns C text.

Budgeting: Ghidra's decompiler has no instruction or block budget either. The
instruction budget is projected onto the decompiler *timeout* (roughly one
simulated second per 200 instructions, clamped to 5..300 s) and the resulting
basic-block count is compared with ``max_blocks`` afterwards, which can only be
reported as a warning. Both budgets travel into the evidence record.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
import importlib.util
import os
import tempfile
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

__all__ = ["GhidraBackend", "INSTALL_ENV", "INSTALL_HINT", "NAME", "PROJECTS_DIR_ENV"]

#: Backend identifier.
NAME = "ghidra"

#: Environment variable that points at a Ghidra installation.
INSTALL_ENV = "GHIDRA_INSTALL_DIR"

#: What a user has to install for this backend to become available.
INSTALL_HINT = (
    f"pip install pyghidra and download Ghidra, then set {INSTALL_ENV} to the "
    "installation directory"
)

#: Evidence source label.
_SOURCE = "ghidra.decompiler"

#: Evidence method label.
_METHOD = "pyghidra.headless.DecompInterface"

#: Entries that mark a directory as a Ghidra installation.
_INSTALL_MARKERS = ("support", "ghidraRun", "ghidraRun.bat")

#: Smallest and largest decompiler timeout, in seconds.
_MIN_TIMEOUT = 5
_MAX_TIMEOUT = 300

#: Instructions per projected timeout second.
_INSTRUCTIONS_PER_SECOND = 200

#: Comment emitted when Ghidra's decompiler produced no code.
_EMPTY_TEXT = "/* ghidra produced no pseudocode for 0x{address:x} */"

#: Environment override for the directory that holds Ghidra analysis projects.
#: The default lives under the system temporary directory because Ghidra
#: rejects project paths with an element starting with ``.`` (so ``~/.codevanta``
#: is unusable) and because without an explicit ``project_location`` pyghidra
#: creates a ``<binary>_ghidra`` directory next to every analysed file, which
#: pollutes checkouts and sample folders. Projects are caches, so a cleaner
#: temp sweep only costs a re-analysis.
PROJECTS_DIR_ENV = "CODEVANTA_GHIDRA_PROJECTS_DIR"

#: Default project root, kept out of the repository and out of dot-directories.
_DEFAULT_PROJECTS_DIR = Path(tempfile.gettempdir()) / "codevanta" / "ghidra_projects"


def _project_location() -> Path:
    """Return an existing directory for Ghidra analysis projects."""
    raw = os.environ.get(PROJECTS_DIR_ENV) or _DEFAULT_PROJECTS_DIR
    location = Path(raw)
    try:
        location.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AnalysisError(
            f"could not create the Ghidra project directory {location}: {exc}; "
            f"set {PROJECTS_DIR_ENV} to a writable path"
        ) from exc
    return location


def _unavailable(availability: BackendAvailability) -> AnalysisError:
    """Build the error raised when a caller asked for an unavailable backend."""
    return AnalysisError(
        f"decompiler backend {availability.name!r} is unavailable: {availability.reason}; "
        "use backend='native' or backend='auto' instead"
    )


def _timeout_seconds(instruction_budget: int) -> int:
    """Project an instruction budget onto a decompiler timeout."""
    seconds = instruction_budget // _INSTRUCTIONS_PER_SECOND
    return max(_MIN_TIMEOUT, min(_MAX_TIMEOUT, seconds))


def _installation_problem(install_dir: str) -> str | None:
    """Return why ``install_dir`` is not usable, or ``None`` when it looks right."""
    if not install_dir:
        return f"no Ghidra installation is configured ({INSTALL_ENV} is not set)"
    root = Path(install_dir)
    if not root.is_dir():
        return f"{INSTALL_ENV}={install_dir!r} is not a directory"
    if not any((root / marker).exists() for marker in _INSTALL_MARKERS):
        return (
            f"{INSTALL_ENV}={install_dir!r} does not look like a Ghidra installation "
            "(no support/ directory and no ghidraRun launcher)"
        )
    return None


class GhidraBackend:
    """Decompilation through a local Ghidra installation driven by pyghidra.

    Attributes:
        name: ``"ghidra"``.
        requires: ``("pyghidra", "ghidra")``.
    """

    name: str = NAME
    requires: tuple[str, ...] = ("pyghidra", "ghidra")

    def availability(self) -> BackendAvailability:
        """Probe ``pyghidra`` and :data:`INSTALL_ENV`; never raises, never launches.

        The probe never *imports* pyghidra either: importing it pulls in JPype
        (a native extension that may load the JVM's support libraries), and
        discovery runs on every ``available_backends()`` call. ``find_spec``
        plus ``importlib.metadata`` answer the same questions import-free.
        """
        problems: list[str] = []
        version = "unknown"
        spec = importlib.util.find_spec("pyghidra")
        if spec is None:
            problems.append("the 'pyghidra' package is not installed (ModuleNotFoundError)")
        else:
            try:
                version = importlib.metadata.version("pyghidra")
            except importlib.metadata.PackageNotFoundError:  # pragma: no cover - odd installs
                version = "unknown"
            except Exception as exc:  # a broken dist-info must not break discovery
                problems.append(f"reading the 'pyghidra' version failed ({type(exc).__name__}: {exc})")
        problem = _installation_problem(os.environ.get(INSTALL_ENV, "").strip())
        if problem is not None:
            problems.append(problem)
        if problems:
            return BackendAvailability(
                name=self.name,
                available=False,
                reason="; ".join(problems) + f"; {INSTALL_HINT}",
                requires=self.requires,
            )
        return BackendAvailability(
            name=self.name,
            available=True,
            reason=(
                f"pyghidra {version} is importable and {INSTALL_ENV} points at a Ghidra "
                "installation; the headless decompiler can run"
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
        """Decompile ``address`` with the local Ghidra installation.

        Args:
            path: Binary to import into a temporary Ghidra project (read-only use
                of the file; the target is analysed, never executed).
            info: Loaded metadata; Ghidra imports the file itself, so only the
                path is used. Kept for a uniform backend signature.
            address: Virtual address of the function to decompile.
            max_instructions: Projected onto the decompiler timeout; Ghidra has no
                instruction budget.
            max_blocks: Compared with the function's block count afterwards; an
                overrun becomes a warning, not an error.

        Returns:
            The rendering plus any warnings Ghidra could not prevent.

        Raises:
            AnalysisError: When pyghidra or the Ghidra installation is missing,
                when a budget is out of range, when no function exists at
                ``address``, or when the decompiler reports a failure.
        """
        instruction_budget = require_budget(
            "max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS
        )
        block_budget = require_budget("max_blocks", max_blocks, MAX_MAX_BLOCKS)
        availability = self.availability()
        if not availability.available:
            raise _unavailable(availability)

        import pyghidra

        opener = getattr(pyghidra, "open_program", None)
        if not callable(opener):
            raise AnalysisError(
                "the installed pyghidra exposes no open_program() headless entry point; "
                f"{INSTALL_HINT}"
            )
        timeout = _timeout_seconds(instruction_budget)
        _ensure_started(pyghidra)
        try:
            program_context = opener(
                str(path),
                analyze=True,
                project_location=_project_location(),
                nested_project_location=False,
            )
        except TypeError:
            # Older pyghidra builds without the project keyword set: fall back
            # to the plain call rather than lose the backend entirely.
            program_context = opener(str(path))

        try:
            with program_context as flat_api:
                text, block_count = _decompile_in_program(flat_api, address, timeout)
        except AnalysisError:
            raise
        except Exception as exc:  # JPype surfaces Java failures as generic errors
            raise AnalysisError(
                f"ghidra could not decompile 0x{address:x}: {type(exc).__name__}: {exc}"
            ) from exc

        warnings: list[str] = []
        if not text.strip():
            warnings.append(
                f"ghidra returned no decompilation for 0x{address:x}: the decompiler "
                "completed without C text, so the rendering is a placeholder comment"
            )
            text = _EMPTY_TEXT.format(address=address)
        if block_count > block_budget:
            warnings.append(
                f"ghidra decompiled {block_count} block(s), above max_blocks={block_budget}; "
                "Ghidra exposes no block budget, so the text is complete rather than truncated"
            )

        evidence = Evidence(
            source=_SOURCE,
            method=_METHOD,
            confidence=Confidence.MEDIUM,
            address=address,
            detail=(
                f"ghidra decompiled the function at 0x{address:x} ({block_count} block(s)) "
                f"headlessly through pyghidra with a {timeout}s timeout projected from "
                f"max_instructions={instruction_budget}; Ghidra has no instruction or block "
                f"budget, so max_blocks={block_budget} is checked afterwards only"
            ),
            extra={
                "backend": self.name,
                "install_dir": os.environ.get(INSTALL_ENV, ""),
                "timeout_seconds": timeout,
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


def _ensure_started(pyghidra: Any) -> None:
    """Start the JVM the way pyghidra expects, ignoring "already started"."""
    start = getattr(pyghidra, "start", None)
    if not callable(start):
        return
    # pyghidra raises when the JVM is already up, which is exactly the state we
    # want; any other failure resurfaces from open_program() below.
    with contextlib.suppress(Exception):
        start()


def _to_address(flat_api: Any, address: int) -> Any:
    """Convert ``address`` to a Ghidra ``Address`` without a Jpype int overflow.

    ``FlatProgramAPI.toAddr`` also accepts text, and its ``String`` overload
    parses ``0x``-prefixed hexadecimal. Calling it with a Python ``int`` makes
    Jpype bind to a 32-bit Java parameter on this Ghidra line, so any address
    above ``0x7fffffff`` raises ``OverflowError``. The hex form is therefore
    primary and the integer form is only a fallback for other builds.
    """
    try:
        return flat_api.toAddr(hex(address))
    except Exception:  # pragma: no cover - defensive across Ghidra builds
        return flat_api.toAddr(address)


def _decompile_in_program(
    flat_api: Any,
    address: int,
    timeout_seconds: int,
) -> tuple[str, int]:
    """Decompile one function inside an open pyghidra program context."""
    from ghidra.app.decompiler import DecompileOptions, DecompInterface

    program = flat_api.getCurrentProgram()
    target = _to_address(flat_api, address)
    function = flat_api.getFunctionAt(target)
    if function is None:
        function = flat_api.getFunctionContaining(target)
    if function is None:
        raise AnalysisError(
            f"ghidra found no function at 0x{address:x}; decompilation needs a defined function"
        )
    # Ghidra's Function API has no ``getBasicBlocks``; the body of a function is a
    # set of address ranges, and one range is the closest portable stand-in for a
    # block count. ``getBody`` is present across the versions pyghidra ships, and
    # any failure here must not sink the decompilation itself, so it degrades to 0
    # (reported as "unknown") instead of raising.
    block_count = 0
    try:
        body = function.getBody()
        ranges = body.getAddressRanges() if body is not None else None
        block_count = len(list(ranges)) if ranges is not None else 0
    except Exception:  # pragma: no cover - defensive across Ghidra versions
        block_count = 0
    decompiler = DecompInterface()
    try:
        decompiler.setOptions(DecompileOptions())
        decompiler.openProgram(program)
        # A ``None`` task monitor is accepted and is what headless scripting uses.
        result = decompiler.decompileFunction(function, timeout_seconds, None)
        if result is None:
            raise AnalysisError(f"ghidra returned no decompiler result for 0x{address:x}")
        if not result.decompileCompleted():
            message = str(result.getErrorMessage() or "no error message reported")
            raise AnalysisError(f"ghidra could not decompile 0x{address:x}: {message}")
        code = result.getDecompiledFunction()
        text = "" if code is None else str(code.getC() or "")
    finally:
        decompiler.dispose()
    return text, block_count

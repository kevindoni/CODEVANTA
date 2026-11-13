"""Live dynamic analysis providers (gdb, frida): probing and script generation.

Dynamic analysis needs a debugger, and a debugger needs a host. This module
therefore does the one part that is *always* safe and deterministic: it decides
whether a provider can run here, and it writes the session script that provider
should execute. Nothing in this module starts a process, imports a provider
package, or touches the target file.

Three questions, three answers
------------------------------
*Can a provider run here?*
    :func:`available_backends` (always ordered ``gdb`` then ``frida``) and
    :func:`provider_status` answer with :class:`DynamicAvailability`. The probe
    uses ``shutil.which`` for the CLI and ``importlib.util.find_spec`` for the
    Frida bindings, and nothing else: Frida is never imported, so probing cannot
    load a native runtime and cannot fail. :attr:`DynamicAvailability.version`
    is consequently always ``None`` -- learning a version would mean running
    ``gdb --version`` or importing ``frida``.
*What should be run?*
    :func:`build_gdb_script` and :func:`build_frida_script` return a
    :class:`DynamicScript`: the script ``text``, the ``entry_commands`` it issues
    at session start, and the ``notes`` that state its limits. Generation is
    pure -- same inputs, same bytes, no file is written -- so a caller can
    snapshot the text in a test or show it in the GUI before anything runs.
*How does the user start it?*
    :func:`attach_command` returns the exact ``argv`` (a tuple, never a shell
    string) for the provider binary, so the CLI, the MCP server and the GUI do
    not each grow their own command line.

Bounded by construction
-----------------------
Both scripts stop after ``max_hits`` hits: gdb increments a convenience counter
and ``quit``s, Frida detaches every listener it installed. gdb prints a fixed
number of backtrace frames (:data:`BACKTRACE_DEPTH`), Frida snapshots a fixed
number of argument registers (:data:`MAX_FRIDA_ARGS`). ``max_hits`` is validated
against :data:`MAX_MAX_HITS` so a typo cannot ask for an unbounded session.

Caller mistakes -- an unknown provider, an empty address list, an address that
is not inside an executable section, an out-of-range ``max_hits`` -- raise
:class:`~codevanta.core.report.AnalysisError` naming the bad input. A missing
debugger is *not* an error: it is reported as ``available=False`` with a
non-empty reason, which is exactly what happens on a machine without gdb or
Frida.
"""


from __future__ import annotations

import importlib.util
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError

__all__ = [
    "BACKTRACE_DEPTH",
    "DEFAULT_MAX_HITS",
    "MAX_FRIDA_ARGS",
    "MAX_MAX_HITS",
    "PROVIDERS",
    "SCRIPT_FILE_NAMES",
    "DynamicAvailability",
    "DynamicScript",
    "attach_command",
    "available_backends",
    "build_frida_script",
    "build_gdb_script",
    "provider_status",
    "script_file_name",
]

#: Supported providers, in the order :func:`available_backends` reports them.
PROVIDERS: tuple[str, ...] = ("gdb", "frida")

#: Default ceiling on recorded hits for a generated script.
DEFAULT_MAX_HITS = 64

#: Hard ceiling on ``max_hits``; a session may never be unbounded.
MAX_MAX_HITS = 100_000

#: Backtrace frames the generated gdb script prints per hit.
BACKTRACE_DEPTH = 8

#: Argument registers the generated Frida hook snapshots per hit.
MAX_FRIDA_ARGS = 4

#: File name each provider's script is expected to be written to. Fixed (not
#: derived from the target) so :func:`attach_command` stays deterministic.
SCRIPT_FILE_NAMES: dict[str, str] = {
    "gdb": "codevanta-session.gdb",
    "frida": "codevanta-hooks.js",
}

#: Registers gdb knows on every target, whatever the architecture.
_STANDARD_REGISTERS: tuple[str, ...] = ("pc", "sp", "fp", "ps")

#: Architecture-specific registers worth snapshotting, keyed by the
#: ``BinaryInfo.architecture`` vocabulary (``x86_64``, ``x86``, ``aarch64``,
#: ``arm``, ``mips``). An unknown architecture adds nothing, so the script falls
#: back to the standard registers alone.


@dataclass(frozen=True)
class DynamicAvailability:
    """Whether one dynamic provider can run in this environment.

    Attributes:
        name: Provider identifier, one of :data:`PROVIDERS`.
        available: ``True`` only when the provider binary the generated script is
            meant for could be located without running it.
        reason: Human-readable explanation. Always non-empty: for an available
            provider it states what was detected (and where), for an unavailable
            one it names the missing piece and how to install it.
        requires: Packages or installations the provider needs, in the order they
            are probed.
        version: Provider version when it can be learned without executing the
            provider. Always ``None`` today, deliberately: probing a version
            would mean running ``gdb`` or importing ``frida``, which is exactly
            what this probe must not do.
    """

    name: str
    available: bool
    reason: str
    requires: tuple[str, ...]
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the probe for the JSON report."""
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
            "requires": list(self.requires),
            "version": self.version,
        }


@dataclass(frozen=True)
class DynamicScript:
    """The script a provider should execute, plus what it will do.

    Attributes:
        provider: Provider the script is written for, one of :data:`PROVIDERS`.
        text: The script itself, ready to be written to
            :data:`SCRIPT_FILE_NAMES` ``[provider]``. Deterministic: the same
            inputs always produce byte-identical text.
        entry_commands: The statements the script issues at session start, in
            order: for gdb the ``set``/``break`` command lines it applies before
            the first breakpoint body, for Frida the per-address
            ``Interceptor.attach`` expression. This is what a user would paste
            into an interactive session to reproduce the script's setup.
        notes: Everything the caller should know before trusting the run: address
            semantics (absolute vs module-relative), hit and backtrace bounds,
            and what the script deliberately does *not* do.
    """

    provider: str
    text: str
    entry_commands: tuple[str, ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the script for the JSON report."""
        return {
            "provider": self.provider,
            "text": self.text,
            "entry_commands": list(self.entry_commands),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Availability probing
# --------------------------------------------------------------------------- #

_FRIDA_INSTALL_HINT = "'pip install frida-tools frida'"
_GDB_INSTALL_HINT = "'apt install gdb' (Linux) or 'brew install gdb' (macOS)"


def _frida_spec() -> object | None:
    """Return the ``frida`` module spec without importing the module."""
    try:
        return importlib.util.find_spec("frida")
    except (ImportError, ValueError):  # pragma: no cover - defensive only
        return None


def _probe_gdb() -> DynamicAvailability:
    executable = shutil.which("gdb")
    if executable:
        return DynamicAvailability(
            name="gdb",
            available=True,
            reason=(
                f"gdb found on PATH ({executable}); the version is not probed, "
                "because probing would run the debugger"
            ),
            requires=("gdb",),
        )
    return DynamicAvailability(
        name="gdb",
        available=False,
        reason=(
            f"gdb is not on PATH; install it with {_GDB_INSTALL_HINT}. "
            "Script generation works without it, only the live session does not"
        ),
        requires=("gdb",),
    )


def _probe_frida() -> DynamicAvailability:
    executable = shutil.which("frida")
    bindings = _frida_spec()
    requires = ("frida", "frida-tools")
    if executable and bindings is not None:
        return DynamicAvailability(
            name="frida",
            available=True,
            reason=(
                f"frida CLI found on PATH ({executable}) and the python bindings are "
                "importable; the version is not probed, because probing would load frida"
            ),
            requires=requires,
        )
    missing: list[str] = []
    if not executable:
        missing.append("the frida CLI")
    if bindings is None:
        missing.append("the frida python bindings")
    return DynamicAvailability(
        name="frida",
        available=False,
        reason=(
            f"frida is not installed: missing {' and '.join(missing)}; "
            f"install with {_FRIDA_INSTALL_HINT}. Script generation works without it, "
            "only the live session does not"
        ),
        requires=requires,
    )


_PROBES = {"gdb": _probe_gdb, "frida": _probe_frida}


def available_backends() -> tuple[DynamicAvailability, ...]:
    """Probe every provider, in :data:`PROVIDERS` order (``gdb`` then ``frida``).

    Never raises and never executes a provider: an absent debugger is reported as
    ``available=False`` with a non-empty :attr:`DynamicAvailability.reason`.
    """
    return tuple(_PROBES[name]() for name in PROVIDERS)


def provider_status(provider: str) -> DynamicAvailability:
    """Probe one provider by name.

    Raises:
        AnalysisError: ``provider`` is not one of :data:`PROVIDERS`.
    """
    probe = _PROBES.get(provider)
    if probe is None:
        raise AnalysisError(
            f"unknown provider {provider!r}; supported providers: {', '.join(PROVIDERS)}"
        )
    return probe()


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #


def _require_target(path: str | Path) -> str:
    """Return ``path`` as text, rejecting an empty target."""
    target = str(path)
    if not target.strip():
        raise AnalysisError("path must be a non-empty target path")
    return target


def _require_max_hits(max_hits: int) -> int:
    """Return ``max_hits`` after checking it is a sane positive bound."""
    if isinstance(max_hits, bool) or not isinstance(max_hits, int):
        raise AnalysisError(
            f"max_hits must be an int, got {type(max_hits).__name__}: {max_hits!r}"
        )
    if max_hits < 1:
        raise AnalysisError(f"max_hits must be >= 1, got {max_hits}")
    if max_hits > MAX_MAX_HITS:
        raise AnalysisError(f"max_hits must be <= {MAX_MAX_HITS}, got {max_hits}")
    return max_hits


def _validate_addresses(
    addresses: Iterable[int], info: BinaryInfo | None
) -> tuple[int, ...]:
    """Return ``addresses`` deduplicated, in order, after full validation.

    Every address must be a positive ``int`` and, when ``info`` is supplied, must
    fall inside a section marked executable. Duplicates collapse to their first
    occurrence so a session installs one breakpoint per address.
    """
    if isinstance(addresses, str | bytes):
        raise AnalysisError("addresses must be an iterable of ints, not text")
    try:
        items = list(addresses)
    except TypeError as exc:
        raise AnalysisError(
            f"addresses must be an iterable of ints, got {type(addresses).__name__}"
        ) from exc
    if not items:
        raise AnalysisError("addresses must not be empty: at least one address is required")
    unique: list[int] = []
    for position, address in enumerate(items):
        if isinstance(address, bool) or not isinstance(address, int):
            raise AnalysisError(
                f"addresses[{position}] must be an int, "
                f"got {type(address).__name__}: {address!r}"
            )
        if address <= 0:
            raise AnalysisError(f"addresses[{position}] must be positive, got {address}")
        if info is not None:
            section = info.section_for_va(address)
            if section is None or not section.is_executable:
                where = "no section" if section is None else f"section {section.name!r}"
                raise AnalysisError(
                    f"addresses[{position}] 0x{address:x} is not inside an executable "
                    f"section ({where})"
                )
        if address not in unique:
            unique.append(address)
    return tuple(unique)


# --------------------------------------------------------------------------- #
# gdb
# --------------------------------------------------------------------------- #

#: How many breakpoints the script header lists before summarising the rest.
_HEADER_ADDRESS_LIMIT = 8


def _summarize_addresses(points: tuple[int, ...]) -> str:
    """Return a short ``0x..., 0x... (+N more)`` summary for a script header."""
    shown = ", ".join(f"0x{address:x}" for address in points[:_HEADER_ADDRESS_LIMIT])
    remainder = len(points) - _HEADER_ADDRESS_LIMIT
    if remainder > 0:
        shown = f"{shown}, ... (+{remainder} more)"
    return shown


def build_gdb_script(
    path: str | Path,
    info: BinaryInfo | None,
    addresses: Iterable[int],
    *,
    max_hits: int = DEFAULT_MAX_HITS,
    follow_forks: bool = False,
) -> DynamicScript:
    """Generate a deterministic, non-interactive gdb command script.

    The script disables pagination, confirmation prompts and ASLR randomisation,
    sets one breakpoint per address, and for every hit prints a line

    ``HIT <address> <reg>=<value> ...``

    (the address is the literal breakpoint address, the register snapshot uses
    gdb's portable ``pc``/``sp``/``fp``/``ps`` plus the binary's own registers),
    then ``BACKTRACE`` followed by :data:`BACKTRACE_DEPTH` ``bt`` frames, and
    finally ``continue``. It exits after ``max_hits`` hits, printing ``LIMIT`` so a
    parser can flag a truncated session, and quits with ``DONE <n> hits``.

    Args:
        path: Target binary. Recorded in the header only; the file is not opened.
        info: Binary metadata. Used to pick architecture-specific registers and to
            check that every address lies in an executable section. ``None`` keeps
            the standard registers and skips the section check.
        addresses: Breakpoint addresses, in file virtual-address space.
        max_hits: Hit ceiling, ``1 <= max_hits <=`` :data:`MAX_MAX_HITS`.
        follow_forks: Follow the child across a ``fork`` instead of staying in the
            parent.

    Raises:
        AnalysisError: An empty address list, a non-``int``/non-positive address,
            an address outside an executable section, an out-of-range ``max_hits``,
            a non-``bool`` ``follow_forks`` or an empty ``path`` -- each message
            names the offending input.

    Returns:
        The script, its ``entry_commands`` (the ``set``/``break`` lines and
        ``run``) and the notes that state its limits.
    """
    target = _require_target(path)
    limit = _require_max_hits(max_hits)
    if not isinstance(follow_forks, bool):
        raise AnalysisError(
            f"follow_forks must be a bool, got {type(follow_forks).__name__}: {follow_forks!r}"
        )
    points = _validate_addresses(addresses, info)

    registers: tuple[str, ...] = _STANDARD_REGISTERS
    if info is not None:
        registers += _ARCH_REGISTERS.get(info.architecture, ())

    fork_mode = "child" if follow_forks else "parent"
    notes = (
        "the script is non-interactive: it starts the target, stops at each breakpoint, "
        "prints one HIT line with a register snapshot plus a short backtrace, and quits",
        "pagination, confirmation prompts and ASLR randomisation are turned off up front "
        "(set pagination off, set confirm off, set disable-randomization on), so nothing "
        "waits for input and the loader does not move the image",
        f"the run stops after {limit} hit(s) and prints a LIMIT line, so raise max_hits to "
        f"record more; at most {BACKTRACE_DEPTH} backtrace frame(s) are printed per hit",
        "breakpoints are absolute file virtual addresses: a PIE/shared image that is not "
        "loaded at its link-time base will not be hit",
        f"forks use set follow-fork-mode {fork_mode} and set detach-on-fork on, so "
        + (
            "the child is followed and the parent detached"
            if follow_forks
            else "gdb stays in the parent and detaches the child"
        ),
        "the register snapshot uses gdb's portable names "
        f"({', '.join(_STANDARD_REGISTERS)})"
        + (
            f" plus the binary's own ({', '.join(registers[len(_STANDARD_REGISTERS):])})"
            if len(registers) > len(_STANDARD_REGISTERS)
            else " only, because no binary metadata was supplied"
        )
        + "; a name gdb does not know aborts that printf line",
        "gdb must be on PATH to run this; available_backends() reports whether it is",
    )

    header = [
        "# CODEVANTA gdb session script -- generated by codevanta.analysis.dynamic",
        "# Do not edit: regenerate with build_gdb_script().",
        f"# target      : {target}",
        "# provider    : gdb",
    ]
    if info is not None:
        header.append(f"# format      : {info.format} {info.architecture} {info.bitness}-bit")
        header.append(f"# image base  : 0x{info.image_base:x}")
    header.extend(
        [
            f"# breakpoints : {len(points)} ({_summarize_addresses(points)})",
            f"# max hits    : {limit}",
            f"# backtrace   : {BACKTRACE_DEPTH} frame(s) per hit",
            f"# follow forks: {'yes (child)' if follow_forks else 'no (parent)'}",
            "# registers   : " + " ".join(registers),
        ]
    )
    header.extend(f"# note: {note}" for note in notes)
    header.append("")

    setup = [
        "set pagination off",
        "set confirm off",
        "set width 0",
        "set height 0",
        "set print elements 0",
        "set breakpoint pending on",
        "set disable-randomization on",
        f"set follow-fork-mode {fork_mode}",
        "set detach-on-fork on",
        "set $cv_hits = 0",
    ]
    breakpoints = [f"break *0x{address:x}" for address in points]
    format_spec = " ".join(f"{name}=%#lx" for name in registers)
    arguments = ", ".join(f"(unsigned long)${name}" for name in registers)

    body = list(setup)
    for address, breakpoint in zip(points, breakpoints, strict=True):
        body.extend(
            [
                breakpoint,
                "commands",
                "  silent",
                "  set $cv_hits = $cv_hits + 1",
                f'  printf "HIT 0x{address:x} {format_spec}\\n", {arguments}',
                '  printf "BACKTRACE\\n"',
                f"  bt {BACKTRACE_DEPTH}",
                f"  if $cv_hits >= {limit}",
                f'    printf "LIMIT {limit} hits reached\\n"',
                "    quit",
                "  end",
                "  continue",
                "end",
            ]
        )
    body.extend(
        [
            "run",
            'printf "DONE %d hits\\n", $cv_hits',
            "quit",
        ]
    )

    return DynamicScript(
        provider="gdb",
        text="\n".join([*header, *body]) + "\n",
        entry_commands=tuple([*setup, *breakpoints, "run"]),
        notes=notes,
    )


_ARCH_REGISTERS: dict[str, tuple[str, ...]] = {
    "x86_64": ("rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"),
    "x86": ("eip", "eax", "ebx", "ecx", "edx", "esi", "edi"),
    "aarch64": ("x0", "x1", "x2", "x3", "x8", "x29", "x30"),
    "arm": ("r0", "r1", "r2", "r3", "r7", "r12"),
    "mips": ("a0", "a1", "a2", "a3", "v0", "v1"),
}



# --------------------------------------------------------------------------- #
# frida
# --------------------------------------------------------------------------- #

def build_frida_script(
    path: str | Path,
    info: BinaryInfo | None,
    addresses: Iterable[int],
    *,
    max_hits: int = DEFAULT_MAX_HITS,
) -> DynamicScript:
    """Generate a deterministic Frida (JavaScript) instrumentation script.

    Addresses are module-relative: each file virtual address is reduced by the
    image base, and the script re-adds ``Module.getBaseAddress(MODULE_NAME)`` at
    run time, so ASLR cannot move a hook off its target. Every hit sends one JSON
    message ``{hit, address, tid, args[0..3]}``; after ``max_hits`` hits every
    listener is detached and an ``{event: "limit"}`` message is sent. The target is
    never killed, and a module that cannot be resolved produces an
    ``{event: "error"}`` message instead of hooking garbage.

    Args:
        path: Target binary. Only its basename is used, as the module name, and the
            path is recorded in the header; the file is not opened.
        info: Binary metadata. **Required** here: the module-relative offset is
            ``address - info.image_base`` and cannot be derived without it.
        addresses: Hook addresses, in file virtual-address space.
        max_hits: Hit ceiling, ``1 <= max_hits <=`` :data:`MAX_MAX_HITS`.

    Raises:
        AnalysisError: ``info`` is ``None``, an address below the image base (so no
            non-negative offset exists), an empty address list, a non-``int`` or
            non-positive address, an address outside an executable section, an
            out-of-range ``max_hits`` or an empty ``path``.

    Returns:
        The script, its ``entry_commands`` (one ``Interceptor.attach`` expression
        per address) and the notes that state its limits.
    """
    target = _require_target(path)
    limit = _require_max_hits(max_hits)
    if info is None:
        raise AnalysisError(
            "build_frida_script needs binary metadata: offsets are module-relative and "
            "cannot be computed without the image base"
        )
    points = _validate_addresses(addresses, info)
    base = info.image_base
    module = Path(target).name
    if not module:
        raise AnalysisError(f"cannot derive a module name from path {target!r}")
    for address in points:
        if address < base:
            raise AnalysisError(
                f"address 0x{address:x} is below the image base 0x{base:x}; it cannot be "
                "expressed as a module-relative offset"
            )

    offsets = {address: address - base for address in points}
    notes = (
        "offsets are module-relative (address - image base) and the script re-adds "
        f"Module.getBaseAddress({module!r}) at run time, so ASLR cannot move a hook",
        "each hit sends one JSON message {hit, address, tid, args} with "
        f"{MAX_FRIDA_ARGS} argument registers; those messages are the only output",
        f"after {limit} hit(s) every listener is detached and an "
        '{event: "limit"} message is sent; the target process is never killed',
        "a module that cannot be resolved produces an "
        '{event: "error"} message instead of hooking garbage',
        "run this with the frida CLI; the python bindings are not needed to generate the "
        "script, only by the live session layer",
    )

    header = [
        "// CODEVANTA Frida session script -- generated by codevanta.analysis.dynamic",
        "// Do not edit: regenerate with build_frida_script().",
        f"// target      : {target}",
        "// provider    : frida",
        f"// format      : {info.format} {info.architecture} {info.bitness}-bit",
        f"// module      : {module}",
        f"// image base  : 0x{base:x}",
        f"// max hits    : {limit}",
        "// hooks       : " + _summarize_addresses(points),
    ]
    header.extend(
        f"//   offset 0x{offset:x} <- 0x{address:x}" for address, offset in offsets.items()
    )
    header.extend(f"// note: {note}" for note in notes)
    header.append("")


    script = [
        "'use strict';",
        "",
        f'var MODULE_NAME = "{module}";',
        f"var MAX_HITS = {limit};",
        f"var ARG_COUNT = {MAX_FRIDA_ARGS};",
        "",
        "var hits = 0;",
        "var base = null;",
        "var listeners = [];",
        "",
        "// Stop observing without touching the target process.",
        "function detachAll() {",
        "  while (listeners.length > 0) {",
        "    var listener = listeners.pop();",
        "    try {",
        "      listener.detach();",
        "    } catch (error) {",
        "      // The hook may already be gone (module unloaded): nothing to undo.",
        "    }",
        "  }",
        "}",
        "",
        "function makeHandler(address) {",
        "  return {",
        "    onEnter: function (args) {",
        "      if (hits >= MAX_HITS) {",
        "        return;",
        "      }",
        "      hits += 1;",
        "      var values = [];",
        "      for (var index = 0; index < ARG_COUNT; index += 1) {",
        "        values.push(args[index].toString());",
        "      }",
        "      send({",
        "        hit: hits,",
        "        address: address,",
        "        tid: Process.getCurrentThreadId(),",
        "        args: values",
        "      });",
        "      if (hits >= MAX_HITS) {",
        '        send({ event: "limit", hits: hits });',
        "        detachAll();",
        "      }",
        "    }",
        "  };",
        "}",
        "",
        "try {",
        "  base = Module.getBaseAddress(MODULE_NAME);",
        "} catch (error) {",
        '  send({ event: "error", message: "module " + MODULE_NAME + " not found: " + error });',
        "  base = null;",
        "}",
        "",
        "if (base !== null) {",
    ]
    hooks = [
        f'Interceptor.attach(base.add(0x{offsets[address]:x}), makeHandler("0x{address:x}"))'
        for address in points
    ]
    script.extend(f"  listeners.push({hook});" for hook in hooks)
    script.append("}")

    return DynamicScript(
        provider="frida",
        text="\n".join([*header, *script]) + "\n",
        entry_commands=tuple(hooks),
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Command lines
# --------------------------------------------------------------------------- #


def script_file_name(provider: str) -> str:
    """Return the fixed file name the provider's script should be written to.

    Raises:
        AnalysisError: ``provider`` is not one of :data:`PROVIDERS`.
    """
    name = SCRIPT_FILE_NAMES.get(provider)
    if name is None:
        raise AnalysisError(
            f"unknown provider {provider!r}; supported providers: {', '.join(PROVIDERS)}"
        )
    return name


def attach_command(
    provider: str,
    path: str | Path,
    script: DynamicScript,
    pid: int | None = None,
) -> tuple[str, ...]:
    """Return the exact ``argv`` that runs ``script`` against ``path``.

    The tuple is ready for ``subprocess.run(..., shell=False)``; it is never a
    shell string, so a path with spaces or quotes cannot be reinterpreted.

    Args:
        provider: ``"gdb"`` or ``"frida"``.
        path: Target binary, spelled the way the provider should see it.
        script: The script this command runs; its provider must match ``provider``
            so a gdb script can never be handed to frida.
        pid: Attach to a running process instead of launching one. Supported for
            ``frida`` only: the generated gdb script ends with ``run``, so a gdb
            command that attaches would not match it.

    Raises:
        AnalysisError: An unknown provider, a script generated for another
            provider, an empty script, an empty path, a non-positive ``pid``, or
            ``pid`` used with ``gdb``.

    Returns:
        ``("gdb", "-q", "-batch", "-x", <script>, "--args", <path>)`` for gdb, or
        ``("frida", "-l", <script>, "-f", <path>)`` (``"-p", <pid>`` when attaching)
        for frida.
    """
    script_file = script_file_name(provider)
    if not isinstance(script, DynamicScript):
        raise AnalysisError(f"script must be a DynamicScript, got {type(script).__name__}")
    if script.provider != provider:
        raise AnalysisError(
            f"script was generated for {script.provider!r}, not {provider!r}; "
            "build the script with the matching builder"
        )
    if not script.text.strip():
        raise AnalysisError(f"script for {provider!r} must not be empty")
    target = _require_target(path)
    if pid is not None:
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise AnalysisError(f"pid must be an int, got {type(pid).__name__}: {pid!r}")
        if pid <= 0:
            raise AnalysisError(f"pid must be positive, got {pid}")
        if provider == "gdb":
            raise AnalysisError(
                "gdb sessions are launch scripts (the script ends with 'run'), so a pid "
                "cannot be used; pass the target path instead"
            )
        return ("frida", "-l", script_file, "-p", str(pid))
    if provider == "gdb":
        return ("gdb", "-q", "-batch", "-x", script_file, "--args", target)
    return ("frida", "-l", script_file, "-f", target)


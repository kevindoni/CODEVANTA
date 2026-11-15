"""MCP tools exposing the emulation, wabt and type-propagation engines.

Three tools, all thin typed wrappers over tested analysis modules (no MCP
imports here): ``codevanta_emulate`` (bounded offline CPU emulation over a
private unicorn instance -- nothing executes on the host; when unicorn is
not installed the run is reported as ``stopped_reason="unsupported"`` with
an honest ``emulator`` availability block instead of a traceback),
``codevanta_wasm`` (the wabt bridge: validation and disassembly of
WebAssembly modules, with the typed missing-tool error naming the wabt
release page when wabt is not on PATH) and ``codevanta_types`` (argument
and return C-type propagation over a bounded disassembly window). The
registration imports live in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import emulate, type_propagation, wabt_bridge
from codevanta.core.disassembler import Disassembler, DisassemblyError
from codevanta.core.loader import BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

# ---- bounded-work limits (mirrored from the wrapped modules) ---------------

#: Instruction budget ``codevanta_emulate`` uses when the caller omits one.
DEFAULT_EMULATE_INSTRUCTIONS = emulate.DEFAULT_MAX_INSTRUCTIONS

#: Stack region ``codevanta_emulate`` maps when the caller omits a size.
DEFAULT_EMULATE_STACK_SIZE = emulate.DEFAULT_STACK_SIZE

#: Hard ceiling on ``codevanta_emulate``'s instruction budget (module-checked).
MAX_EMULATE_INSTRUCTIONS = emulate.MAX_MAX_INSTRUCTIONS

#: Disassembly window ``codevanta_types`` decodes when the caller omits one.
DEFAULT_TYPES_INSTRUCTIONS = 256

#: Hard ceiling on ``codevanta_types``'s disassembly window.
MAX_TYPES_INSTRUCTIONS = 4096

#: Default wall-clock budget for one wabt invocation, in seconds.
DEFAULT_WASM_TIMEOUT = wabt_bridge.DEFAULT_TIMEOUT

#: Modes ``codevanta_wasm`` accepts.
WASM_MODES = ("validate", "objdump")

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "mcp.expose"

#: Widest x86 instruction, in bytes (the read window per requested instruction).
_MAX_INSTRUCTION_BYTES = 15

#: Description for the ``codevanta_emulate`` MCP tool.
TOOL_DESCRIPTION_EMULATE = (
    "Emulate one function by bounded offline CPU emulation (unicorn): the "
    "image sections are mapped into a private emulator, registers start at "
    "the ABI defaults plus caller seeds, and the run ends with an honest "
    "stop reason (return/budget/unmapped/unsupported/error), the final "
    "register snapshot, recorded memory writes and indirect branch "
    "targets. Nothing ever executes on the host. When the optional "
    "emulation extra is missing the result says so instead of failing "
    "(pip install codevanta[emulation])."
)

#: Description for the ``codevanta_wasm`` MCP tool.
TOOL_DESCRIPTION_WASM = (
    "Analyze a WebAssembly module with the wabt toolkit: mode=validate "
    "runs wasm-validate and reports the verdict plus parsed error lines "
    "(a module that FAILS validation is a result, not a tool failure); "
    "mode=objdump runs wasm-objdump -d and returns the section headers "
    "and a bounded instruction listing. Needs wabt on PATH "
    "(https://github.com/WebAssembly/wabt/releases); its absence is a "
    "typed error naming the release page, never a traceback."
)

#: Description for the ``codevanta_types`` MCP tool.
TOOL_DESCRIPTION_TYPES = (
    "Infer the C argument and return types of one function from register "
    "use (heuristic type propagation): a bounded window is disassembled at "
    "the address and every use of an ABI argument register (dereference, "
    "scaled index, arithmetic, copy, compare) becomes a type witness, with "
    "the most specific rule winning and the losing observations kept in "
    "the evidence note. The return type comes from the last write to "
    "rax/eax before the first ret. Nothing is executed."
)


def _require_file(path: str) -> Path:
    """Return ``path`` as a :class:`~pathlib.Path` or raise the typed error.

    The loader would raise :class:`~codevanta.core.loader.BinaryLoadError`
    with its own wording; the MCP convention is the exact message
    ``file not found: <path>`` as an
    :class:`~codevanta.core.report.AnalysisError`.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {path}")
    return target


def _load_binary(target: Path) -> Any:
    """Load ``target`` and map :class:`BinaryLoadError` onto the typed error."""
    try:
        return BinaryLoader().load(target)
    except BinaryLoadError as exc:
        raise AnalysisError(f"cannot load {target}: {exc}") from exc


def codevanta_emulate(
    path: str,
    address: int,
    initial_registers: dict[str, int] | None = None,
    max_instructions: int = DEFAULT_EMULATE_INSTRUCTIONS,
    stack_size: int = DEFAULT_EMULATE_STACK_SIZE,
) -> dict[str, Any]:
    """Run one bounded emulation of the function at ``address``.

    The bytes of ``path`` are mapped into a private unicorn CPU at their
    virtual addresses (nothing executes on the host) and the run is bounded
    by ``max_instructions`` (1..:data:`MAX_EMULATE_INSTRUCTIONS`,
    module-checked) and ``stack_size``. When unicorn is not installed the
    result comes back with ``stopped_reason="unsupported"`` and an
    ``emulator`` block reporting availability honestly, instead of an
    error.
    """
    target = _require_file(path)
    info = _load_binary(target)
    result = emulate.emulate_function(
        target,
        info,
        address,
        initial_registers=dict(initial_registers) if initial_registers else None,
        max_instructions=max_instructions,
        stack_size=stack_size,
    )
    payload = result.to_dict()
    payload["path"] = str(target)
    payload["emulator"] = {
        "available": emulate.EMULATOR_AVAILABLE,
        "status": emulate.emulator_status(),
    }
    return payload


def codevanta_wasm(
    path: str,
    mode: str = "validate",
    timeout: float = DEFAULT_WASM_TIMEOUT,
    out_dir: str | None = None,
    runner: wabt_bridge.Runner | None = None,
    which: Any = None,
) -> dict[str, Any]:
    """Validate or disassemble one WebAssembly module with wabt.

    ``mode="validate"`` runs ``wasm-validate`` and reports ``valid`` plus
    the parsed error lines; ``mode="objdump"`` runs ``wasm-objdump -d`` and
    returns section headers plus a bounded instruction listing (with
    ``out_dir`` the raw transcript is preserved). Both degrade gracefully:
    when wabt is not on PATH the typed error is
    :data:`codevanta.analysis.wabt_bridge.WABT_MISSING_MESSAGE`. ``runner``
    and ``which`` are injectable stand-ins for tests; the MCP wrapper never
    exposes them.
    """
    action = str(mode).strip().lower()
    if action not in WASM_MODES:
        raise AnalysisError(f"mode must be one of {list(WASM_MODES)}, not {mode!r}")
    target = _require_file(path)
    if action == "validate":
        verdict = wabt_bridge.wasm_validate(
            target, timeout=timeout, runner=runner, which=which
        )
        payload = verdict.to_dict()
    else:
        listing = wabt_bridge.wasm_objdump(
            target, timeout=timeout, runner=runner, which=which, out_dir=out_dir
        )
        payload = listing.to_dict()
    payload["mode"] = action
    payload["wabt_available"] = wabt_bridge.wasm_available()
    return payload


def codevanta_types(
    path: str,
    address: int,
    abi: str = "sysv",
    max_instructions: int = DEFAULT_TYPES_INSTRUCTIONS,
) -> dict[str, Any]:
    """Propagate C argument/return types for the function at ``address``.

    A bounded window (1..:data:`MAX_TYPES_INSTRUCTIONS` instructions) is
    disassembled from ``path`` at ``address`` and fed through
    :func:`codevanta.analysis.type_propagation.infer_argument_types` and
    :func:`codevanta.analysis.type_propagation.infer_return_type`. Nothing
    is executed; every emitted type carries the observation that produced
    it. ``abi`` selects the argument registers (``sysv`` or ``ms64``; a
    32-bit binary always uses ``ecx``/``edx``).
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an int, not {type(address).__name__}")
    if address <= 0:
        raise AnalysisError(f"address must be positive, got 0x{address:x}")
    if isinstance(max_instructions, bool) or not isinstance(max_instructions, int):
        raise AnalysisError("max_instructions must be an int")
    if not 1 <= max_instructions <= MAX_TYPES_INSTRUCTIONS:
        raise AnalysisError(
            f"max_instructions must be between 1 and {MAX_TYPES_INSTRUCTIONS}, "
            f"got {max_instructions}"
        )
    target = _require_file(path)
    info = _load_binary(target)
    section = info.section_for_va(address)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{address:x} is not inside an executable section")
    code = read_code(target, info, address, max_instructions * _MAX_INSTRUCTION_BYTES)
    try:
        disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
        decoded = disassembler.disassemble(
            code, base_address=address, max_instructions=max_instructions
        )
    except DisassemblyError as exc:
        raise AnalysisError(f"cannot disassemble 0x{address:x}: {exc}") from exc
    instructions = decoded.instructions
    if not instructions:
        raise AnalysisError(f"no instruction decoded at 0x{address:x}")
    pointer_width = 8 if info.bitness >= 64 else 4
    arguments = type_propagation.infer_argument_types(
        instructions, pointer_width, abi=abi
    )
    return_type = type_propagation.infer_return_type(instructions, pointer_width)
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="type_propagation",
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"{len(arguments)} argument type(s) and return type "
            f"{return_type.c_type} from {len(instructions)} instruction(s) "
            f"decoded at 0x{address:x}; heuristic from register use, "
            "nothing is executed"
        ),
        extra={
            "pointer_width": pointer_width,
            "abi": abi,
            "instruction_count": len(instructions),
            "max_instructions": max_instructions,
            "truncated": decoded.truncated,
        },
    )
    return {
        "path": str(target),
        "address": f"0x{address:x}",
        "pointer_width": pointer_width,
        "abi": abi,
        "instruction_count": len(instructions),
        "truncated": decoded.truncated,
        "arguments": [argument.to_dict() for argument in arguments],
        "return_type": return_type.to_dict(),
        "evidence": evidence.to_dict(),
    }

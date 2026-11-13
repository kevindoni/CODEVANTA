"""MCP tool implementations (plain functions, no MCP imports)."""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any

from codevanta.analysis.binary_diff import (
    DEFAULT_SEMANTIC_THRESHOLD,
    MAX_SEMANTIC_THRESHOLD,
    MIN_SEMANTIC_THRESHOLD,
    diff_binaries,
)
from codevanta.analysis.callgraph import MAX_LIMIT as MAX_CALLGRAPH_LIMIT
from codevanta.analysis.callgraph import build_call_graph
from codevanta.analysis.cfg import build_cfg
from codevanta.analysis.debuginfo import DEFAULT_LIMIT as DEFAULT_DWARF_LIMIT
from codevanta.analysis.debuginfo import MAX_LIMIT as MAX_DWARF_LIMIT
from codevanta.analysis.debuginfo import extract_debug_info
from codevanta.analysis.decompile import (
    DEFAULT_MAX_BLOCKS as DEFAULT_DECOMPILE_MAX_BLOCKS,
)
from codevanta.analysis.decompile import (
    DEFAULT_MAX_INSTRUCTIONS as DEFAULT_DECOMPILE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompile import MAX_MAX_BLOCKS as MAX_DECOMPILE_MAX_BLOCKS
from codevanta.analysis.decompile import (
    MAX_MAX_INSTRUCTIONS as MAX_DECOMPILE_MAX_INSTRUCTIONS,
)
from codevanta.analysis.decompilers import BackendResult, supported_backends
from codevanta.analysis.decompilers import (
    decompile_function as decompile_with_backend,
)
from codevanta.analysis.function_hash import function_fingerprint, function_similarity
from codevanta.analysis.jump_tables import MAX_ENTRIES as MAX_JUMP_TABLE_ENTRIES
from codevanta.analysis.jump_tables import MODE_RELATIVE, resolve_jump_table
from codevanta.analysis.jump_tables import MODES as JUMP_TABLE_MODES
from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_FIELDS,
    MAX_MAX_INSTRUCTIONS,
    suggest_struct,
)
from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs
from codevanta.core.entropy import (
    DEFAULT_MAX_SAMPLE_BYTES,
    MAX_SAMPLE_LIMIT,
    PACKED_HINT_THRESHOLD,
    analyze_entropy,
)
from codevanta.core.functions import discover_functions
from codevanta.core.report import (
    MAX_DISASSEMBLY_COUNT,
    MAX_STRING_LIMIT,
    AnalysisError,
    build_report,
    disassemble_region,
    load_binary,
    resolve_target,
)
from codevanta.core.strings import StringExtractor
from codevanta.storage.session import MAX_LIMIT as MAX_SESSION_LIMIT
from codevanta.storage.session import SessionError, SessionStore

#: Environment variable that overrides the default session database location.
SESSION_DB_ENV = "CODEVANTA_DB"

#: Hard ceiling on reportable cross references so one call cannot exhaust memory.
MAX_XREF_LIMIT = 200_000

#: Hard ceiling on executable bytes decoded by one cross-reference scan (64 MiB).
MAX_XREF_BYTES = 64_000_000

#: Hard ceiling on the numeric limits of the comparison, jump-table and
#: fingerprint tools, so no single call can be asked for unbounded work.
MAX_TOOL_LIMIT = 20_000

#: Backend requested when the caller does not name one: pick the best available.
AUTO_BACKEND = "auto"

#: Decompiler backends :func:`decompile` accepts: ``auto`` plus every registered
#: provider (``ghidra``, ``angr``, ``native``). Read from the provider registry so
#: adding a backend never drifts from the accepted set.
DECOMPILE_BACKENDS: tuple[str, ...] = (AUTO_BACKEND, *supported_backends())

#: Prefix of the block-coverage line the native renderer writes in its header.
_HEADER_BLOCKS_PREFIX = " * blocks: "

#: Default session database file used when no explicit path is supplied.
DEFAULT_SESSION_DB = Path.home() / ".codevanta" / "sessions.db"


def _validate_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def _resolve_session_db(db: str | Path | None) -> Path:
    """Return ``db``, else ``$CODEVANTA_DB``, else ``~/.codevanta/sessions.db``."""
    if db is not None:
        if isinstance(db, Path):
            return db
        if not isinstance(db, str):
            raise SessionError(
                f"db must be a string or Path, not {type(db).__name__}"
            )
        text = db.strip()
        if not text:
            raise SessionError("db must not be empty")
        return Path(text).expanduser()
    configured = os.environ.get(SESSION_DB_ENV)
    if configured and configured.strip():
        return Path(configured.strip()).expanduser()
    return DEFAULT_SESSION_DB


def binary_info(path: str) -> dict[str, Any]:
    """Return format, architecture, sections, imports, exports, and symbols."""
    return load_binary(_validate_path(path)).to_dict()


def functions(path: str, limit: int = 200) -> dict[str, Any]:
    """Return function candidates with detection source and confidence."""
    if limit < 1 or limit > 100_000:
        raise AnalysisError("limit must be between 1 and 100000")
    info = load_binary(_validate_path(path))
    candidates = discover_functions(info)
    return {
        "count": len(candidates),
        "returned": min(limit, len(candidates)),
        "truncated": len(candidates) > limit,
        "items": [candidate.to_dict() for candidate in candidates[:limit]],
    }


def strings(path: str, min_length: int = 4, limit: int = 200) -> dict[str, Any]:
    """Return ASCII and UTF-16LE strings with file offset and mapped VA."""
    if min_length < 1:
        raise AnalysisError("min_length must be >= 1")
    if limit < 1 or limit > MAX_STRING_LIMIT:
        raise AnalysisError(f"limit must be between 1 and {MAX_STRING_LIMIT}")
    target = _validate_path(path)
    info = load_binary(target)
    results = StringExtractor(min_length=min_length).extract(target, info=info, limit=limit)
    return {
        "count": len(results),
        "limit": limit,
        "items": [item.to_dict() for item in results],
    }


def disasm(
    path: str,
    address: int | None = None,
    function: str | None = None,
    count: int = 50,
) -> dict[str, Any]:
    """Disassemble the entry point, a virtual address, or a named function."""
    if count < 1 or count > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"count must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, address, function)
    result = disassemble_region(target, info, start, count=count)
    return {
        "start": f"0x{start:x}",
        "count": len(result.instructions),
        "truncated": result.truncated,
        "instructions": [instruction.to_dict() for instruction in result.instructions],
        "evidence": result.evidence.to_dict(),
    }


def analyze(
    path: str,
    string_limit: int = 5000,
    include_xrefs: bool = False,
    include_cfg: bool = False,
    include_callgraph: bool = False,
) -> dict[str, Any]:
    """Return the analysis report; phase 2 sections are opt-in per flag.

    Mirrors the CLI ``analyze`` flags: the base report always carries binary
    metadata, functions, strings, entry-point disassembly, and provenance;
    ``include_xrefs`` / ``include_cfg`` / ``include_callgraph`` add the phase 2
    sections agents would otherwise fetch through the dedicated tools.
    """
    return build_report(
        _validate_path(path),
        string_limit=string_limit,
        include_xrefs=include_xrefs,
        include_cfg=include_cfg,
        include_callgraph=include_callgraph,
    )


def entropy(
    path: str,
    threshold: float = PACKED_HINT_THRESHOLD,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
) -> dict[str, Any]:
    """Return per-section Shannon entropy with packing triage hints."""
    if not 0.0 < threshold <= 8.0:
        raise AnalysisError("threshold must be in (0, 8]")
    if max_sample_bytes < 1 or max_sample_bytes > MAX_SAMPLE_LIMIT:
        raise AnalysisError(f"max_sample_bytes must be between 1 and {MAX_SAMPLE_LIMIT}")
    target = _validate_path(path)
    info = load_binary(target)
    return analyze_entropy(
        target, info, threshold=threshold, max_sample_bytes=max_sample_bytes
    ).to_dict()


def xrefs(
    path: str,
    limit: int = 200,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Return direct call, jump, and branch cross references with evidence."""
    if limit < 1 or limit > MAX_XREF_LIMIT:
        raise AnalysisError(f"limit must be between 1 and {MAX_XREF_LIMIT}")
    if max_bytes < 1 or max_bytes > MAX_XREF_BYTES:
        raise AnalysisError(f"max_bytes must be between 1 and {MAX_XREF_BYTES}")
    target = _validate_path(path)
    info = load_binary(target)
    result = find_xrefs(target, info, max_bytes=max_bytes)
    total = len(result.xrefs)
    items = [xref.to_dict() for xref in result.xrefs[:limit]]
    return {
        "count": total,
        "returned": len(items),
        "truncated": result.truncated or total > limit,
        "items": items,
        "scanned_bytes": result.scanned_bytes,
        "warnings": list(result.warnings),
    }


def cfg(
    path: str,
    address: int | None = None,
    function: str | None = None,
    max_instructions: int = 2000,
    max_blocks: int = 500,
) -> dict[str, Any]:
    """Build a linear-sweep control-flow graph for an address or named function."""
    if max_instructions < 1 or max_instructions > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(
            f"max_instructions must be between 1 and {MAX_DISASSEMBLY_COUNT}"
        )
    if max_blocks < 1 or max_blocks > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"max_blocks must be between 1 and {MAX_DISASSEMBLY_COUNT}")
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, address, function)
    graph = build_cfg(
        target,
        info,
        start,
        max_instructions=max_instructions,
        max_blocks=max_blocks,
    )
    return {
        "start": f"0x{start:x}",
        "blocks": [block.to_dict() for block in graph.blocks],
        "instruction_count": graph.instruction_count,
        "truncated": graph.truncated,
        "warnings": list(graph.warnings),
    }


def _rendered_block_count(result: BackendResult) -> int | None:
    """Return how many basic blocks the rendering covered, when it says so.

    The external backends record their block count in ``evidence.extra`` because
    their C output has no header. The native renderer instead publishes it in the
    pseudo-C header comment (`` * blocks: N  instructions: M``), the same comment
    block :mod:`codevanta.analysis.decompilers.base` scans for warnings, so the
    count is read from there. ``None`` means the backend reported no coverage.
    """
    recorded = result.evidence.extra.get("block_count")
    if isinstance(recorded, int) and not isinstance(recorded, bool):
        return recorded
    for line in result.text.splitlines():
        if line == " */":
            break
        if not line.startswith(_HEADER_BLOCKS_PREFIX):
            continue
        field = line[len(_HEADER_BLOCKS_PREFIX) :].split(" ", 1)[0]
        if field.isdigit():
            return int(field)
    return None


def decompile(
    path: str,
    address: int,
    backend: str = AUTO_BACKEND,
    max_instructions: int = DEFAULT_DECOMPILE_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_DECOMPILE_MAX_BLOCKS,
) -> dict[str, Any]:
    """Render one function as C-like text with the requested decompiler backend.

    ``backend="auto"`` (the default) prefers a real decompiler -- Ghidra, then
    angr -- when one is installed and falls back to the built-in mnemonic-level
    pseudo-C renderer, recording every skipped backend in ``warnings``, so a
    fallback is never silent. ``backend="native"`` always runs; ``"angr"`` and
    ``"ghidra"`` are strict: when that backend is unavailable the call raises
    instead of substituting another provider. A missing optional dependency never
    surfaces as ``ImportError``: it becomes an :class:`AnalysisError` naming the
    backend, the probe's reason and the install hint.

    Control flow, argument count and types are inferred from mnemonics; nothing
    is mapped or executed, so the text is LOW-confidence evidence rather than a
    recovered source file.

    Args:
        path: PE or ELF file to read; it is read, never executed.
        address: Virtual address of the function's first instruction, inside an
            executable section.
        backend: ``"auto"`` (default), ``"native"``, ``"angr"`` or ``"ghidra"``;
            matched case-insensitively, and blank means ``"auto"``.
        max_instructions: Instruction budget (1 ..
            :data:`codevanta.analysis.decompile.MAX_MAX_INSTRUCTIONS`).
        max_blocks: Block budget (1 ..
            :data:`codevanta.analysis.decompile.MAX_MAX_BLOCKS`).

    Returns:
        The backend result -- ``text``, ``backend`` (the provider that actually
        rendered it, which differs from the request under ``"auto"``),
        ``language``, ``warnings`` and ``evidence`` -- plus the resolved
        ``path``, the resolved ``address`` as ``"0x..."``, and ``blocks``, the
        number of basic blocks the text covers.

    Raises:
        AnalysisError: If the file is missing, ``address`` is not a non-negative
            integer, ``backend`` is not one of :data:`DECOMPILE_BACKENDS`, a
            budget is out of range, the strictly requested backend is
            unavailable (the message names it), or the resolved address is not
            executable code.
    """
    start = _check_address(address)
    if not isinstance(backend, str):
        raise AnalysisError(f"backend must be a string, got {type(backend).__name__}")
    selected = backend.strip().lower() or AUTO_BACKEND
    if selected not in DECOMPILE_BACKENDS:
        raise AnalysisError(
            f"backend must be one of {', '.join(DECOMPILE_BACKENDS)}, got {backend!r}"
        )
    instruction_budget = _check_bounded_int(
        "max_instructions", max_instructions, MAX_DECOMPILE_MAX_INSTRUCTIONS
    )
    block_budget = _check_bounded_int(
        "max_blocks", max_blocks, MAX_DECOMPILE_MAX_BLOCKS
    )
    target = _validate_path(path)
    info = load_binary(target)
    result = decompile_with_backend(
        target,
        info,
        start,
        backend=selected,
        max_instructions=instruction_budget,
        max_blocks=block_budget,
    )
    payload = result.to_dict()
    payload["path"] = str(info.path)
    payload["address"] = f"0x{start:x}"
    payload["blocks"] = _rendered_block_count(result)
    return payload


def _check_callgraph_limit(name: str, value: int) -> None:
    """Raise :class:`AnalysisError` unless ``value`` is a limit in 1..MAX_LIMIT."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer")
    if value < 1 or value > MAX_CALLGRAPH_LIMIT:
        raise AnalysisError(f"{name} must be between 1 and {MAX_CALLGRAPH_LIMIT}")


def callgraph(
    path: str,
    limit_functions: int = 1000,
    limit_edges: int = 5000,
) -> dict[str, Any]:
    """Build an inter-function call graph from resolved call cross references.

    Edges come from direct calls only, plus calls through a pointer slot that
    resolves to a known import (the node is labelled with the import name) or
    to a statically known slot with an unknown callee. Jumps, conditional
    branches, and indirect calls whose slot is not known statically produce no
    edges. The caller of a call site is attributed heuristically to the nearest
    function candidate at or below the call address in the same section, so
    caller attribution is not proven.

    Args:
        path: PE or ELF file to analyse; it is read, never executed.
        limit_functions: Maximum number of function candidates kept as nodes
            (1 .. 200000). Dropping candidates marks the graph truncated.
        limit_edges: Maximum number of deduplicated call edges reported
            (1 .. 200000).

    Returns:
        The serialized graph with ``nodes``, ``edges``, ``truncated``,
        ``evidence``, and ``warnings``.

    Raises:
        AnalysisError: If the file is missing or a limit is out of range.
    """
    _check_callgraph_limit("limit_functions", limit_functions)
    _check_callgraph_limit("limit_edges", limit_edges)
    target = _validate_path(path)
    info = load_binary(target)
    graph = build_call_graph(
        target,
        info,
        functions=discover_functions(info),
        max_functions=limit_functions,
        max_edges=limit_edges,
    )
    return graph.to_dict()


def _check_bounded_int(
    name: str,
    value: int,
    maximum: int = MAX_TOOL_LIMIT,
) -> int:
    """Return ``value`` when it is a plain integer in ``1 .. maximum``, else raise.

    Args:
        name: Argument name used in the error message.
        value: Caller-supplied value; booleans are rejected even though ``bool``
            is an ``int`` subclass, because ``True`` is never a valid limit.
        maximum: Inclusive upper bound for ``value``.

    Returns:
        ``value`` unchanged.

    Raises:
        AnalysisError: If ``value`` is not a non-boolean ``int``, or if it falls
            outside ``1 .. maximum``.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer")
    if value < 1 or value > maximum:
        raise AnalysisError(f"{name} must be between 1 and {maximum}")
    return value


def _check_bool(name: str, value: bool) -> bool:
    """Return ``value`` when it is a real ``bool``, else raise.

    Args:
        name: Argument name used in the error message.
        value: Caller-supplied flag; strings, integers and ``None`` are rejected
            so a truthy value can never silently switch a mode on.

    Returns:
        ``value`` unchanged.

    Raises:
        AnalysisError: If ``value`` is not a ``bool``.
    """
    if not isinstance(value, bool):
        raise AnalysisError(f"{name} must be a boolean")
    return value


def _check_threshold(name: str, value: float) -> float:
    """Return ``value`` as a float when it is a finite number in ``0.0 .. 1.0``.

    Args:
        name: Argument name used in the error message.
        value: Caller-supplied similarity floor; booleans are rejected even
            though ``bool`` is an ``int`` subclass, because ``True`` is not a
            score, and ``NaN``/``inf`` are rejected because they can never be
            compared meaningfully.

    Returns:
        ``value`` converted to ``float``, unchanged in magnitude.

    Raises:
        AnalysisError: If ``value`` is not a non-boolean real number, or if it
            is non-finite or outside ``0.0 .. 1.0``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(
            f"{name} must be a number between {MIN_SEMANTIC_THRESHOLD} and "
            f"{MAX_SEMANTIC_THRESHOLD}, got {type(value).__name__}"
        )
    number = float(value)
    if not math.isfinite(number) or not (
        MIN_SEMANTIC_THRESHOLD <= number <= MAX_SEMANTIC_THRESHOLD
    ):
        raise AnalysisError(
            f"{name} must be between {MIN_SEMANTIC_THRESHOLD} and "
            f"{MAX_SEMANTIC_THRESHOLD}, got {value!r}"
        )
    return number


def _check_address(address: int) -> int:
    """Return ``address`` when it is a non-negative plain integer, else raise.

    Args:
        address: Virtual address supplied by the caller.

    Returns:
        ``address`` unchanged.

    Raises:
        AnalysisError: If ``address`` is not a non-boolean ``int`` or is negative.
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"address must be an integer, got {address!r}")
    if address < 0:
        raise AnalysisError(f"address must be non-negative, got {address}")
    return address


def diff(
    left: str,
    right: str,
    max_functions: int = 5000,
    deep: bool = False,
    semantic: bool = False,
    threshold: float = DEFAULT_SEMANTIC_THRESHOLD,
) -> dict[str, Any]:
    """Compare two binaries structurally and report per-side deltas.

    Both files are parsed only; nothing is mapped or executed. Functions are
    matched by virtual address first and, for the leftovers, by name after
    moving. ``identical`` means no function, section, import or export delta was
    observed -- equal file hashes are neither required nor implied.

    Args:
        left: Path of the left-hand binary; it is read, never executed.
        right: Path of the right-hand binary; it is read, never executed.
        max_functions: Per-side ceiling on the compared function candidates
            (1 .. 20000). Any truncation is reported in ``warnings``.
        deep: When true, additionally fingerprint the normalized instruction
            shape of address-matched functions and mark differing digests as
            ``changed``. Digests are shape fingerprints: equal is not byte
            equality and different is not a semantic difference.
        semantic: When true, additionally score the functions that address and
            name matching left unpaired. The best pairs whose normalized
            instruction shapes overlap at or above ``threshold`` become one
            ``changed`` entry carrying ``similarity``, so a moved function can
            be reported as moved instead of removed-plus-added. A score is shape
            evidence, not proof that the two functions are the same code.
        threshold: Smallest similarity score in ``0.0 .. 1.0`` that may pair two
            leftovers (default ``0.9``). It is validated in every mode, so an
            out-of-range value raises even when ``semantic`` is false.

    Returns:
        The serialized comparison with ``left_path``, ``right_path``,
        ``identical``, the added/removed/changed function and section lists, the
        import and export deltas, ``evidence``, and ``warnings``. With
        ``semantic`` true the evidence ``extra`` record also carries the
        effective ``semantic_threshold``.

    Raises:
        AnalysisError: If either file is missing, ``max_functions`` is out of
            range, ``deep`` or ``semantic`` is not a boolean, or ``threshold``
            is not a finite number within ``0.0 .. 1.0``.
    """
    left_path = _validate_path(left)
    right_path = _validate_path(right)
    limit = _check_bounded_int("max_functions", max_functions)
    deep_flag = _check_bool("deep", deep)
    semantic_flag = _check_bool("semantic", semantic)
    # Validate the floor even in structural mode so the argument contract does
    # not depend on which mode was selected, and so a bad score cannot cost two
    # full loads.
    score_floor = _check_threshold("threshold", threshold)
    comparison = diff_binaries(
        left_path,
        right_path,
        max_functions=limit,
        deep=deep_flag,
        semantic=semantic_flag,
        threshold=score_floor,
    )
    return comparison.to_dict()


def jump_table(
    path: str,
    address: int,
    mode: str = "absolute",
    base: int | None = None,
    entries: int = 256,
    executable_only: bool = True,
) -> dict[str, Any]:
    """Decode a jump table at an absolute virtual address.

    ``mode="absolute"`` reads consecutive pointer-sized virtual addresses;
    ``mode="relative"`` reads consecutive signed 32-bit offsets and resolves each
    one as ``base + offset``. In both layouts the scan stops at the first slot
    that cannot be a usable target and records why in ``warnings``: a target no
    section maps, a target outside an executable section when
    ``executable_only`` is true, or -- in absolute mode only -- a zero pointer,
    the conventional terminator. A zero offset in relative mode is a real delta,
    so it terminates nothing.

    Entries carry medium confidence: a run of same-width slots found by shape is
    evidence of a dispatch table, not proof that a dispatcher indexes it.

    Args:
        path: PE or ELF file to read; it is read, never executed.
        address: Absolute virtual address of the first slot, which must be
            backed by file bytes of a mapped section.
        mode: ``"absolute"`` (default) or ``"relative"``, case-insensitive.
        base: Origin the signed offsets are added to. Required for
            ``"relative"`` and ignored for ``"absolute"``.
        entries: Maximum number of slots to decode (1 .. 20000, further capped by
            the resolver ceiling
            :data:`codevanta.analysis.jump_tables.MAX_ENTRIES`).
        executable_only: When true (default), a target inside a non-executable
            section ends the scan with a warning.

    Returns:
        The serialized table with ``table_address``, ``entry_count``,
        ``entries``, ``pointer_size``, ``truncated``, ``warnings``, and
        ``evidence``.

    Raises:
        AnalysisError: If the file is missing, ``address`` or ``base`` is not a
            non-negative integer, ``mode`` is unknown, ``entries`` is out of
            range, or ``executable_only`` is not a boolean.
    """
    table_address = _check_address(address)
    if not isinstance(mode, str):
        raise AnalysisError(f"mode must be a string, got {type(mode).__name__}")
    normalized = mode.strip().lower()
    if normalized not in JUMP_TABLE_MODES:
        raise AnalysisError(
            f"mode must be one of {', '.join(JUMP_TABLE_MODES)}, got {mode!r}"
        )
    base_address: int | None = None
    if normalized == MODE_RELATIVE:
        if base is None:
            raise AnalysisError("base is required when mode is 'relative'")
        base_address = _check_address(base)
    limit = _check_bounded_int("entries", entries)
    if limit > MAX_JUMP_TABLE_ENTRIES:
        raise AnalysisError(f"entries too large (limit {MAX_JUMP_TABLE_ENTRIES})")
    flag = _check_bool("executable_only", executable_only)
    target = _validate_path(path)
    info = load_binary(target)
    result = resolve_jump_table(
        target,
        info,
        table_address,
        max_entries=limit,
        executable_only=flag,
        mode=normalized,
        base_address=base_address,
    )
    return result.to_dict()


def function_hash(
    path: str,
    address: int,
    max_instructions: int = 2000,
) -> dict[str, Any]:
    """Fingerprint the normalized instruction shape of a function region.

    The region is decoded with a bounded linear sweep from ``address`` and each
    instruction is rendered as ``"<mnemonic> <operands>"`` with every numeric
    literal masked to ``#``. The masked stream is hashed with SHA-256, so two
    functions with the same mnemonic/operand structure share a digest even when
    their immediates, branch targets or frame offsets differ.

    Equal digests are therefore **not** byte equality, and different digests are
    **not** a semantic difference. ``truncated`` marks a digest that covers only
    a prefix of the region.

    Args:
        path: PE or ELF file to read; it is read, never executed.
        address: Virtual address of the first instruction, inside an executable
            section.
        max_instructions: Instruction budget (1 .. 20000); the sweep reads at
            most ``max_instructions * 16`` file bytes.

    Returns:
        The serialized fingerprint with ``address``, ``algorithm``, ``digest``,
        ``instruction_count``, ``truncated``, and ``evidence``.

    Raises:
        AnalysisError: If the file is missing, ``address`` is not a non-negative
            integer or is not inside an executable section, or
            ``max_instructions`` is out of range.
    """
    start = _check_address(address)
    limit = _check_bounded_int("max_instructions", max_instructions)
    target = _validate_path(path)
    info = load_binary(target)
    fingerprint = function_fingerprint(
        target,
        info,
        start,
        max_instructions=limit,
    )
    return fingerprint.to_dict()


def _check_side_address(side: str, address: int) -> int:
    """Return ``address`` when it is a non-negative plain integer, else raise.

    Args:
        side: Argument name (``address_a`` or ``address_b``) used in the error
            message, so a two-address tool names the offending side.
        address: Virtual address supplied by the caller.

    Returns:
        ``address`` unchanged.

    Raises:
        AnalysisError: If ``address`` is not a non-boolean ``int`` or is negative.
    """
    if isinstance(address, bool) or not isinstance(address, int):
        raise AnalysisError(f"{side} must be an integer, got {address!r}")
    if address < 0:
        raise AnalysisError(f"{side} must be non-negative, got {address}")
    return address


def similarity(
    path_a: str,
    address_a: int,
    path_b: str,
    address_b: int,
    max_instructions: int = 2000,
) -> dict[str, Any]:
    """Compare two function regions by normalized instruction *shape*.

    Each region is decoded with the same bounded linear sweep as
    :func:`codevanta.mcp_server.tools.function_hash` and its instructions are
    normalized to ``"<mnemonic> <masked operands>"``, with every numeric literal
    masked to ``#``. The two token streams are compared as multisets::

        shared = sum((left & right).values())   # sum(min), shared occurrences
        union  = sum((left | right).values())   # sum(max), union size
        score  = shared / union

    The score is therefore in ``[0, 1]``: ``1.0`` means both sides share every
    token with the same multiplicity and ``0.0`` means they share none.
    Multiplicity matters (``nop; nop; ret`` is only partially similar to
    ``nop; ret``). Because immediates, frame offsets and branch targets are
    masked, a relocated or recompiled copy of a function usually scores
    ``1.0`` -- and structurally similar but semantically unrelated code can too.

    The score is **shape evidence at medium confidence, never semantic
    equivalence**: it says nothing about what the code does, and a genuine
    rewrite scores low.

    Args:
        path_a: Left-hand PE or ELF file; it is read, never executed.
        address_a: Virtual address of the left region's first instruction,
            inside an executable section.
        path_b: Right-hand PE or ELF file; it is read, never executed.
        address_b: Virtual address of the right region's first instruction,
            inside an executable section.
        max_instructions: Per-side instruction budget (1 .. 20000); each sweep
            reads at most ``max_instructions * 16`` file bytes.

    Returns:
        The serialized comparison with ``score``, ``shared``, ``left_total``,
        ``right_total``, ``union``, ``warnings``, and ``evidence``. A warning
        means that side was truncated, so only prefixes were compared.

    Raises:
        AnalysisError: If either file is missing, either address is not a
            non-negative integer or is not inside an executable section, or
            ``max_instructions`` is out of range.
    """
    start_a = _check_side_address("address_a", address_a)
    start_b = _check_side_address("address_b", address_b)
    limit = _check_bounded_int("max_instructions", max_instructions)
    target_a = _validate_path(path_a)
    target_b = _validate_path(path_b)
    info_a = load_binary(target_a)
    info_b = load_binary(target_b)
    comparison = function_similarity(
        target_a,
        info_a,
        start_a,
        target_b,
        info_b,
        start_b,
        max_instructions=limit,
    )
    return comparison.to_dict()


def dwarf(
    path: str,
    limit: int = DEFAULT_DWARF_LIMIT,
) -> dict[str, Any]:
    """Extract DWARF debug-info functions and named types with evidence."""
    if limit < 1 or limit > MAX_DWARF_LIMIT:
        raise AnalysisError(f"limit must be between 1 and {MAX_DWARF_LIMIT}")
    target = _validate_path(path)
    info = load_binary(target)
    return extract_debug_info(target, info, limit=limit).to_dict()


def struct(
    path: str,
    address: int | None = None,
    function: str | None = None,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_fields: int = DEFAULT_MAX_FIELDS,
    include_stack: bool = False,
) -> dict[str, Any]:
    """Suggest struct fields from the memory operands of a function region.

    The region is decoded with a bounded linear sweep from the resolved start and
    every memory operand of the form ``[reg]``, ``[reg + 0xNN]`` or
    ``[reg - 0xNN]`` is read: the displacement becomes a field offset, the Intel
    size keyword on the operand (falling back to the pointer width) becomes the
    field width, and the operand position decides read versus write -- the first
    operand is a write, except for ``cmp``/``test``/``cmps*``, which are always
    reads. Operands with an index register, a scale or a segment prefix are
    skipped rather than guessed, and ``lea``/``nop`` carry no memory access.

    Accesses are aggregated per offset: the dominant width is the most frequent
    one (ties go to the wider access) and the read/write counts are totals for
    the offset. Fields are returned sorted by ascending offset, so the result is
    deterministic for a given input. ``alignment`` is the gcd of the absolute
    non-zero offsets (``None`` with fewer than two distinct non-zero offsets) and
    ``array_groups`` lists maximal runs of at least three equally wide, equally
    spaced fields, computed from the fields actually reported.

    Every field is a **heuristic** at ``Confidence.MEDIUM``: a hypothesis about
    how one function treats memory around one base register, never a verified
    type, and it says nothing about signedness, purpose or lifetime. Fields are
    not proven to belong to a single struct when several base registers are in
    play; each entry names its own ``base_register``.

    Args:
        path: PE or ELF file to read; it is read, never executed.
        address: Virtual address of the first instruction, inside an executable
            section. Takes precedence over ``function``.
        function: Name of a detected function candidate to start from; used only
            when ``address`` is ``None``.
        max_instructions: Instruction budget (1 ..
            :data:`codevanta.analysis.type_recovery.MAX_MAX_INSTRUCTIONS`); the
            sweep reads at most ``max_instructions * 16`` file bytes.
        max_fields: Field cap (1 ..
            :data:`codevanta.analysis.type_recovery.MAX_MAX_FIELDS`). Dropped
            offsets set ``truncated``.
        include_stack: When true, ``rbp``/``rsp``-relative operands are reported
            alongside register-based ones; when false (default) they are ignored
            as stack slots.

    Returns:
        The serialized suggestion with ``address``, ``instruction_count``,
        ``field_count``, ``max_fields``, ``truncated``, ``include_stack``,
        ``fields``, ``alignment``, ``array_groups``, and ``evidence``.

    Raises:
        AnalysisError: If the file is missing, ``address`` is not a non-negative
            integer, ``function`` is not a string or names no candidate, a limit
            is out of range, ``include_stack`` is not a boolean, or the resolved
            start is not inside an executable section.
    """
    start_address: int | None = None
    if address is not None:
        start_address = _check_address(address)
    if function is not None and not isinstance(function, str):
        raise AnalysisError(
            f"function must be a string, got {type(function).__name__}"
        )
    instruction_budget = _check_bounded_int(
        "max_instructions", max_instructions, MAX_MAX_INSTRUCTIONS
    )
    field_cap = _check_bounded_int("max_fields", max_fields, MAX_MAX_FIELDS)
    stack_flag = _check_bool("include_stack", include_stack)
    target = _validate_path(path)
    info = load_binary(target)
    start = resolve_target(info, start_address, function)
    suggestion = suggest_struct(
        target,
        info,
        start,
        max_instructions=instruction_budget,
        max_fields=field_cap,
        include_stack=stack_flag,
    )
    return suggestion.to_dict()


def session_save(
    path: str,
    db: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Analyze a binary and persist its fingerprint and counts as a session."""
    target = _validate_path(path)
    db_path = _resolve_session_db(db)
    info = load_binary(target)
    functions_count = len(discover_functions(info))
    strings_count = len(StringExtractor(min_length=4).extract(target, info=info))
    with SessionStore(db_path) as store:
        record = store.save(info, functions_count, strings_count, notes=notes)
    return {"session": record.to_dict(), "db": str(db_path)}


def session_list(db: str | None = None, limit: int = 20) -> dict[str, Any]:
    """List stored sessions newest first from the session database."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise SessionError("limit must be an integer")
    if limit < 1 or limit > MAX_SESSION_LIMIT:
        raise SessionError(f"limit must be between 1 and {MAX_SESSION_LIMIT}")
    db_path = _resolve_session_db(db)
    with SessionStore(db_path) as store:
        records = store.list(limit=limit)
    return {
        "count": len(records),
        "items": [record.to_dict() for record in records],
        "db": str(db_path),
    }

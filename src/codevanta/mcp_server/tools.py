"""MCP tool implementations (plain functions, no MCP imports)."""

from __future__ import annotations

import json
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
from codevanta.analysis.compare import (
    COMPARE_WHATS,
    BundleCompare,
    InventoryCompare,
    StringsCompare,
    compare_bundles,
    compare_inventories,
    compare_strings,
    is_bundle_document,
    load_document,
    load_report_payload,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_FUNCTIONS as COMPARE_MAX_FUNCTIONS,
)
from codevanta.analysis.compare import (
    DEFAULT_MAX_STRINGS as COMPARE_MAX_STRINGS,
)
from codevanta.analysis.dataflow import (
    DEFAULT_MAX_BLOCKS as DEFAULT_DATAFLOW_MAX_BLOCKS,
)
from codevanta.analysis.dataflow import (
    DEFAULT_MAX_INSTRUCTIONS as DEFAULT_DATAFLOW_MAX_INSTRUCTIONS,
)
from codevanta.analysis.dataflow import (
    MAX_MAX_BLOCKS as MAX_DATAFLOW_MAX_BLOCKS,
)
from codevanta.analysis.dataflow import (
    MAX_MAX_INSTRUCTIONS as MAX_DATAFLOW_MAX_INSTRUCTIONS,
)
from codevanta.analysis.dataflow import analyze_dataflow
from codevanta.analysis.debug_session import (
    DEBUG_ACTIONS,
    run_debug,
)
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
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_PATHS as DEFAULT_SYMBOLIC_MAX_PATHS,
)
from codevanta.analysis.symbolic import (
    DEFAULT_MAX_STEPS as DEFAULT_SYMBOLIC_MAX_STEPS,
)
from codevanta.analysis.symbolic import (
    MAX_MAX_PATHS as MAX_SYMBOLIC_MAX_PATHS,
)
from codevanta.analysis.symbolic import (
    MAX_MAX_STEPS as MAX_SYMBOLIC_MAX_STEPS,
)
from codevanta.analysis.symbolic import explore_paths
from codevanta.analysis.trace import (
    MAX_TRACE_HITS,
    MAX_TRACE_LINES,
    parse_frida_trace,
    parse_gdb_trace,
)
from codevanta.analysis.type_recovery import (
    DEFAULT_MAX_FIELDS,
    DEFAULT_MAX_INSTRUCTIONS,
    MAX_MAX_FIELDS,
    MAX_MAX_INSTRUCTIONS,
    suggest_struct,
)
from codevanta.analysis.vtables import (
    DEFAULT_MAX_SLOTS,
    DEFAULT_MAX_TABLES,
    DEFAULT_MIN_SLOTS,
    find_vtables,
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
from codevanta.core.unknowns import (
    DEFAULT_UNKNOWN_SEVERITY,
    UNKNOWN_STATUSES,
    make_open_unknown,
    records_from_payload,
    records_to_payload,
    resolve_unknowns,
)
from codevanta.mcp_server.ext_meta import (
    codevanta_metadata as codevanta_metadata,  # lane-meta: ONE MCP registration line
)
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

#: Trace formats :func:`trace` accepts; ``auto`` reads the provider off the file.
AUTO_TRACE_PROVIDER = "auto"
TRACE_PROVIDERS: tuple[str, ...] = (AUTO_TRACE_PROVIDER, "gdb", "frida")

#: Hard ceiling on the bytes one call reads from a saved trace (8 MiB).
MAX_TRACE_BYTES = 8_000_000

#: Lines ``auto`` inspects before it decides it cannot identify the provider.
TRACE_DETECT_LINES = 200

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


def _validate_trace_path(trace_path: str) -> Path:
    """Return ``trace_path`` as an existing regular file, or raise naming it.

    The binary has :func:`_validate_path`; a saved trace needs its own wording
    because ``file not found: x`` would not say which of the two inputs was
    wrong, and a caller that mixed them up would chase the wrong argument.

    Args:
        trace_path: Path to the saved session capture.

    Returns:
        The path, confirmed to exist and to be a regular file.

    Raises:
        AnalysisError: If ``trace_path`` is not a non-empty string, does not
            exist, or is not a regular file.
    """
    if not isinstance(trace_path, str):
        raise AnalysisError(
            f"trace_path must be a string, got {type(trace_path).__name__}"
        )
    text = trace_path.strip()
    if not text:
        raise AnalysisError("trace_path must not be empty")
    candidate = Path(text).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"trace file not found: {trace_path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular trace file: {trace_path}")
    return candidate


def _read_trace_text(source: Path) -> tuple[str, bool]:
    """Read a saved trace, bounded to :data:`MAX_TRACE_BYTES`.

    The cut deliberately never lands mid-line: when the byte budget ends the
    read, everything after the last newline is dropped, so a bounded read cannot
    invent a malformed ``HIT`` line or a half JSON message that would then show
    up as a bogus warning.

    Args:
        source: Trace file already validated by :func:`_validate_trace_path`.

    Returns:
        ``(text, byte_cut)``: the decoded capture (invalid UTF-8 replaced, never
        raised) and whether the byte budget stopped the read early.

    Raises:
        AnalysisError: If the file cannot be opened or read.
    """
    try:
        with source.open("rb") as handle:
            raw = handle.read(MAX_TRACE_BYTES + 1)
    except OSError as exc:
        raise AnalysisError(f"cannot read trace file {str(source)!r}: {exc}") from exc
    byte_cut = len(raw) > MAX_TRACE_BYTES
    if byte_cut:
        raw = raw[:MAX_TRACE_BYTES]
        newline = raw.rfind(b"\n")
        if newline >= 0:
            raw = raw[: newline + 1]
    return raw.decode("utf-8", errors="replace"), byte_cut


def _detect_trace_provider(text: str) -> str | None:
    """Return which provider wrote ``text``, or ``None`` when nothing matches.

    Detection reads the file shape, not a flag: a line that parses as a JSON
    object is one of the messages the Frida hook sends, and a line opening with
    ``HIT``/``BACKTRACE``/``LIMIT``/``DONE`` is one the gdb script prints. Only
    the first :data:`TRACE_DETECT_LINES` lines are inspected, so a large capture
    costs no more than a small one, and an unrecognisable file returns ``None``
    instead of being guessed onto whichever provider has more markers.

    This is the same rule ``codevanta trace --provider auto`` applies, restated
    here rather than imported because the MCP layer must not depend on the CLI.

    Args:
        text: The captured trace.

    Returns:
        ``"gdb"``, ``"frida"``, or ``None`` when neither shape is recognised.
    """
    markers = ("HIT ", "BACKTRACE", "LIMIT ", "DONE ")
    for line in text.splitlines()[:TRACE_DETECT_LINES]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                message = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(message, dict):
                return "frida"
            continue
        if stripped.startswith(markers):
            return "gdb"
    return None


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


def vtable(
    path: str,
    address: int | None = None,
    scan: bool = False,
    min_slots: int = DEFAULT_MIN_SLOTS,
    max_slots: int = DEFAULT_MAX_SLOTS,
    max_tables: int = DEFAULT_MAX_TABLES,
    resolve_thunks: bool = True,
) -> dict[str, Any]:
    """Discover vtable candidates and resolve thunk chains (indirect xrefs).

    ``address`` decodes one candidate at an exact vtable address (the optional
    two-slot Itanium header is skipped automatically); ``scan`` sweeps every
    non-executable data section for runs of consecutive code pointers. Slot
    targets that are one-instruction tail-call thunks report their final
    callee as ``resolved_target``. Every candidate is a heuristic with
    ``vtable.candidate`` / ``vtable.slot_ref`` evidence at medium confidence.
    """
    if scan and address is not None:
        raise AnalysisError("use either address or scan, not both")
    if address is None and not scan:
        raise AnalysisError("give address or scan=True")
    if min_slots < 1 or min_slots > 64:
        raise AnalysisError("min_slots must be between 1 and 64")
    if max_slots < min_slots or max_slots > 4_096:
        raise AnalysisError("max_slots must be between min_slots and 4096")
    if max_tables < 1 or max_tables > 1024:
        raise AnalysisError("max_tables must be between 1 and 1024")
    target = _validate_path(path)
    info = load_binary(target)
    return find_vtables(
        target,
        info,
        address=address,
        min_slots=min_slots,
        max_slots=max_slots,
        max_tables=max_tables,
        resolve_thunks=resolve_thunks,
    ).to_dict()


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


def trace(
    path: str,
    trace_path: str,
    provider: str = AUTO_TRACE_PROVIDER,
    max_hits: int | None = None,
) -> dict[str, Any]:
    """Replay a saved dynamic-session trace and map its hits onto functions.

    Nothing is launched: ``trace_path`` is what a generated gdb or Frida session
    script already printed, so one capture can be re-read offline as often as
    needed and a session never has to be repeated to re-analyse it. The binary and
    the capture are read, never executed.

    ``provider`` selects the format. ``auto`` (the default) reads it off the file
    shape -- a JSON object line is a Frida message, a ``HIT``/``BACKTRACE``/
    ``LIMIT``/``DONE`` line is gdb -- and the choice comes back as
    ``provider_resolved``. A capture that cannot be placed is an error rather
    than a guess, and so is an explicit ``provider`` that contradicts the file.

    Every hit is attributed to the :func:`discover_functions` candidate that
    encloses its address; a hit outside every candidate stays unattributed
    instead of being guessed onto the nearest symbol. Hits are evidence of one
    run, not proof that the branch executes in production.

    Work is bounded: at most :data:`MAX_TRACE_BYTES` bytes are read,
    :data:`codevanta.analysis.trace.MAX_TRACE_LINES` lines are parsed, and at
    most ``max_hits`` hits are kept. A cut of any kind sets ``truncated`` and is
    explained in ``warnings``; malformed lines become warnings too and never
    fail the call.

    Args:
        path: PE or ELF file the session ran against.
        trace_path: Saved gdb output or Frida JSON-lines capture.
        provider: ``"auto"``, ``"gdb"`` or ``"frida"``.
        max_hits: Hit budget (1 ..
            :data:`codevanta.analysis.trace.MAX_TRACE_HITS`) or ``None`` for the
            parser default. Hits past it are counted in ``total_hits`` but not
            kept, and ``truncated`` is set.

    Returns:
        ``TraceReport.to_dict()`` -- ``provider``, ``hits``, ``total_hits``,
        ``truncated``, ``unique_addresses``, ``function_coverage``, ``warnings``
        and ``evidence`` -- plus ``path``, ``trace_path`` and
        ``provider_resolved``.

    Raises:
        AnalysisError: If a path is missing or unreadable, the trace file is not
            a regular file, ``provider`` is not one of :data:`TRACE_PROVIDERS`,
            the provider cannot be resolved, the capture contradicts the
            requested provider, or ``max_hits`` is out of range.
    """
    if provider not in TRACE_PROVIDERS:
        raise AnalysisError(
            f"provider must be one of {', '.join(TRACE_PROVIDERS)}, got {provider!r}"
        )
    hit_limit = (
        None
        if max_hits is None
        else _check_bounded_int("max_hits", max_hits, MAX_TRACE_HITS)
    )
    target = _validate_path(path)
    source = _validate_trace_path(trace_path)
    text, byte_cut = _read_trace_text(source)

    detected = _detect_trace_provider(text)
    if provider == AUTO_TRACE_PROVIDER:
        if detected is None:
            raise AnalysisError(
                f"cannot tell whether {str(source)!r} is a gdb or a frida trace; "
                "pass provider='gdb' or provider='frida'"
            )
        resolved = detected
    elif detected is not None and detected != provider:
        raise AnalysisError(
            f"provider mismatch: {str(source)!r} is a {detected} trace, not {provider}"
        )
    else:
        resolved = provider

    info = load_binary(target)
    functions = discover_functions(info)
    if resolved == "gdb":
        report = parse_gdb_trace(
            text,
            info=info,
            functions=functions,
            max_lines=MAX_TRACE_LINES,
            max_hits=hit_limit,
        )
    else:
        report = parse_frida_trace(
            text,
            info=info,
            functions=functions,
            max_lines=MAX_TRACE_LINES,
            max_hits=hit_limit,
        )

    payload = report.to_dict()
    if byte_cut:
        payload["truncated"] = True
        payload["warnings"] = [
            *payload["warnings"],
            f"trace truncated to the first {MAX_TRACE_BYTES} byte(s)",
        ]
    payload["path"] = str(target)
    payload["trace_path"] = str(source)
    payload["provider_resolved"] = resolved
    return payload


def debug(
    path: str,
    action: str = "registers",
    break_at: str | None = None,
    address: int | None = None,
    length: int = 64,
    max_frames: int = 20,
    transport: Any = None,
) -> dict[str, Any]:
    """Run one live gdb debug session: launch the target, act, verified exit.

    Unlike every other tool here, this one *executes* something: it owns a
    ``gdb --interpreter=mi2`` process for the duration of the call, inserting
    an optional breakpoint (``break_at`` names a function or an address), running
    the target to it, performing ``action`` at the stop, then shutting the
    debugger down and verifying it exited. gdb missing is a typed error, never
    an ImportError: the error names what to install.

    Actions: ``registers`` (default; the register file at the stop),
    ``memory`` (needs ``address``, reads ``length`` bytes, capped at
    MAX_MEMORY_BYTES), ``backtrace`` (capped at MAX_BACKTRACE_FRAMES frames),
    ``continue``, ``step``, ``next`` and ``quit`` (launch, optionally break,
    exit). Every payload carries an ``evidence`` record naming the MI command
    that produced it; everything is evidence of one run, not a static
    property of the binary.

    Args:
        path: Program for gdb to load.
        action: One of :data:`DEBUG_ACTIONS`.
        break_at: Optional function name or ``0x``-address to break at first.
        address: Virtual address for the ``memory`` action.
        length: Bytes the ``memory`` action reads (1 .. MAX_MEMORY_BYTES).
        max_frames: Backtrace budget (1 .. MAX_BACKTRACE_FRAMES).
        transport: Injectable MI transport (tests); ``None`` launches gdb.

    Returns:
        ``target``, ``break`` (breakpoint plus the stop it produced, when
        requested), ``action``, ``result`` and the verified ``quit`` payload.

    Raises:
        AnalysisError: An unknown action, an action/argument mismatch, an
            out-of-range length or frame budget, a missing gdb executable, or
            any MI-level refusal (each names the offending input).
    """
    if action not in DEBUG_ACTIONS:
        raise AnalysisError(f"action must be one of {', '.join(DEBUG_ACTIONS)}, got {action!r}")
    target = _validate_path(path)
    if break_at is not None and (not isinstance(break_at, str) or not break_at.strip()):
        raise AnalysisError(f"break_at must be a function name or an address, got {break_at!r}")
    return run_debug(
        target,
        action=action,
        break_at=break_at,
        address=address,
        length=length,
        max_frames=max_frames,
        transport=transport,
    )


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


def symbolic(
    path: str,
    address: int,
    max_paths: int = DEFAULT_SYMBOLIC_MAX_PATHS,
    max_steps: int = DEFAULT_SYMBOLIC_MAX_STEPS,
) -> dict[str, Any]:
    """Explore the paths through a function with the unicorn explorer.

    This is a **unicorn exploration**, not a symbolic executor: every path is a
    sequence of branch decisions replayed on a freshly initialised unicorn CPU,
    and only the file's own image bytes ever run -- the host never executes the
    target. Only x86 and x86-64 are emulated, and the optional unicorn extra
    must be installed. What each direction is worth, stated honestly: the side
    of a conditional the real emulation takes comes back with
    ``basis: "observed"``; the other side is produced by rewriting the flag or
    counter that guards the branch and comes back ``basis: "seeded"`` -- it is
    assumed feasible, never proven, because no path predicate is built, no
    constraint is solved and there is no symbolic variable anywhere in the
    engine. All values are concrete, so a path is evidence about one concrete
    run of the code, never proof of reachability for arbitrary inputs. Every
    seeded direction is named in the path's ``warnings``, counted in
    ``seeded_branches``, listed in the evidence ``assumptions``, and the whole
    summary drops to ``low`` confidence as soon as any direction was seeded.

    Args:
        path: PE or ELF file to read; its bytes are only ever run inside the
            emulator, never on the host.
        address: Virtual address of the first instruction, inside an
            executable section with file bytes.
        max_paths: Path budget (1 ..
            :data:`codevanta.analysis.symbolic.MAX_MAX_PATHS`).
        max_steps: Instruction budget for the whole exploration, replays
            included (1 .. :data:`codevanta.analysis.symbolic.MAX_MAX_STEPS`).

    Returns:
        ``PathExploration.to_dict()`` -- ``address``, ``explorer``,
        ``architecture``, ``bitness``, ``max_paths``, ``max_steps``,
        ``steps``, ``complete``, ``paths``, ``unresolved``, ``return_values``,
        ``entries``, ``warnings`` and ``evidence`` -- plus ``path`` and the
        resolved start as ``address_resolved``.

    Raises:
        AnalysisError: If the file is missing, ``address`` is not a
            non-negative integer or not inside an executable, mapped, readable
            section, a budget is out of range or not an integer, unicorn is
            not installed, or the architecture is not x86/x86-64.
    """
    start = _check_address(address)
    path_limit = _check_bounded_int("max_paths", max_paths, MAX_SYMBOLIC_MAX_PATHS)
    step_limit = _check_bounded_int("max_steps", max_steps, MAX_SYMBOLIC_MAX_STEPS)
    target = _validate_path(path)
    info = load_binary(target)
    exploration = explore_paths(
        target,
        info,
        start,
        max_paths=path_limit,
        max_steps=step_limit,
    )
    payload = exploration.to_dict()
    payload["path"] = str(target)
    payload["address_resolved"] = f"0x{start:x}"
    return payload


def dataflow(
    path: str,
    address: int,
    max_instructions: int = DEFAULT_DATAFLOW_MAX_INSTRUCTIONS,
    max_blocks: int = DEFAULT_DATAFLOW_MAX_BLOCKS,
) -> dict[str, Any]:
    """Recover definition-use chains, constants and reaching definitions.

    The recursive CFG is built from ``address`` and walked once, forward: each
    instruction contributes its read uses, resolved against the definitions
    seen so far, and each register write becomes one definition that kills
    whatever the register held before. Constants are folded only from shapes
    the pass itself proves -- immediates, RIP-relative ``lea``/``mov`` targets,
    copies of known values and ``add``/``sub``/``xor`` over two known values --
    so ``constant_registers`` never guesses. Reads with no reaching definition
    in the region are absent from ``reaching_definition`` and reported in
    ``warnings`` instead.

    Honest limits: the pass is a linearization of the CFG, not a fixpoint --
    state flows into a block from its highest-addressed predecessor, so a join
    is approximated rather than merged. What is reported stays sound one
    definition at a time (a value is only folded where the summary proves it,
    and only the last definition of a register survives), but the summary is
    not a dataflow proof over the whole function. Two calls with the same
    arguments always produce the same result.

    Args:
        path: PE or ELF file to read; it is read, never executed.
        address: Virtual address of the first instruction, inside an
            executable section.
        max_instructions: Instruction budget (1 ..
            :data:`codevanta.analysis.dataflow.MAX_MAX_INSTRUCTIONS`).
        max_blocks: Block budget (1 ..
            :data:`codevanta.analysis.dataflow.MAX_MAX_BLOCKS`).

    Returns:
        ``DataFlowSummary.to_dict()`` -- ``address``, ``definition_count``,
        ``use_count``, ``definitions``, ``uses``, ``constant_registers``,
        ``reaching_definition``, ``warnings`` and ``evidence``.

    Raises:
        AnalysisError: If the file is missing, ``address`` is not a
            non-negative integer or not inside an executable section, or a
            budget is out of range or not an integer.
    """
    start = _check_address(address)
    instruction_budget = _check_bounded_int(
        "max_instructions", max_instructions, MAX_DATAFLOW_MAX_INSTRUCTIONS
    )
    block_budget = _check_bounded_int(
        "max_blocks", max_blocks, MAX_DATAFLOW_MAX_BLOCKS
    )
    target = _validate_path(path)
    info = load_binary(target)
    summary = analyze_dataflow(
        target,
        info,
        start,
        max_instructions=instruction_budget,
        max_blocks=block_budget,
    )
    return summary.to_dict()


def _load_ledger_payload(ledger_path: Path) -> dict[str, Any]:
    """Read a ledger file, unwrapping a bundle's ``unknowns`` entry if present."""
    document = load_document(ledger_path)
    if is_bundle_document(document):
        entry = document["entries"].get("unknowns")
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), dict):
            raise AnalysisError(f"{ledger_path} is a bundle without an 'unknowns' entry")
        document = entry["payload"]
    return document


def _write_ledger_payload(ledger_path: Path, payload: dict[str, Any]) -> None:
    """Write a ledger payload as canonical JSON (sorted keys, trailing newline)."""
    try:
        ledger_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise AnalysisError(f"cannot write ledger {ledger_path}: {exc}") from exc


def compare(
    a: str,
    b: str,
    what: str = "functions",
    max_functions: int = COMPARE_MAX_FUNCTIONS,
    max_strings: int = COMPARE_MAX_STRINGS,
) -> dict[str, Any]:
    """Compare two offline JSON artifacts (reports or evidence bundles).

    ``what="functions"`` and ``what="strings"`` compare analyze report payloads
    (a bundle document is unwrapped to its ``report`` entry automatically);
    ``what="bundles"`` diffs two evidence-bundle documents by record kind and
    digest membership. Nothing is executed or disassembled: the comparison is
    reproducible from the two documents alone, and every result carries an
    evidence record stating how far the claim reaches.
    """
    if what not in COMPARE_WHATS:
        raise AnalysisError(f"unknown --what {what!r}; expected one of {', '.join(COMPARE_WHATS)}")
    left_path = _validate_path(a)
    right_path = _validate_path(b)
    result: InventoryCompare | StringsCompare | BundleCompare
    if what == "functions":
        result = compare_inventories(
            load_report_payload(left_path),
            load_report_payload(right_path),
            max_functions=max_functions,
        )
    elif what == "strings":
        result = compare_strings(
            load_report_payload(left_path),
            load_report_payload(right_path),
            max_strings=max_strings,
        )
    else:
        left_document = load_document(left_path)
        right_document = load_document(right_path)
        if not is_bundle_document(left_document):
            raise AnalysisError(f"{a} is not an evidence-bundle document")
        if not is_bundle_document(right_document):
            raise AnalysisError(f"{b} is not an evidence-bundle document")
        result = compare_bundles(left_document, right_document)
    return result.to_dict()


def unknowns(
    action: str,
    ledger: str,
    unknown_id: str | None = None,
    domain: str | None = None,
    summary: str | None = None,
    severity: str = DEFAULT_UNKNOWN_SEVERITY,
    evidence_refs: list[str] | None = None,
    note: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Manage the residual-unknown ledger at ``ledger`` (a JSON file).

    ``action="list"`` returns the records (optionally filtered by ``status``);
    ``action="open"`` appends one typed open record built from ``domain`` /
    ``summary`` / ``severity`` / ``evidence_refs`` (the ledger file is created
    when missing); ``action="resolve"`` closes ``unknown_id`` with ``note``.
    Ids are deterministic content digests, so opening the same finding twice
    is refused as a duplicate.
    """
    if action not in ("list", "open", "resolve"):
        raise AnalysisError(f"unknown action {action!r}; expected list, open or resolve")
    if status is not None and status not in UNKNOWN_STATUSES:
        raise AnalysisError(
            f"unknown status {status!r}; expected one of {', '.join(UNKNOWN_STATUSES)}"
        )
    ledger_path = Path(ledger).expanduser()

    if action == "open":
        if not domain or not summary:
            raise AnalysisError("opening an unknown requires domain and summary")
        existing: list[Any] = []
        if ledger_path.exists():
            existing = list(records_from_payload(_load_ledger_payload(ledger_path)))
        record = make_open_unknown(
            domain=domain,
            summary=summary,
            severity=severity,
            evidence_refs=tuple(evidence_refs or ()),
        )
        payload = records_to_payload([*existing, record])
        _write_ledger_payload(ledger_path, payload)
        return {
            "action": "open",
            "record": record.to_dict(),
            "count": int(payload["count"]),
        }

    if not ledger_path.exists():
        raise AnalysisError(f"ledger {ledger_path} does not exist")
    document = _load_ledger_payload(ledger_path)

    if action == "list":
        records = records_from_payload(document)
        if status is not None:
            records = tuple(record for record in records if record.status == status)
        listing = records_to_payload(list(records))
        return {
            "action": "list",
            "count": int(listing["count"]),
            "items": listing["items"],
        }

    # action == "resolve"
    if not unknown_id:
        raise AnalysisError("resolving an unknown requires unknown_id")
    payload = resolve_unknowns(document, [unknown_id], note=note or "")
    _write_ledger_payload(ledger_path, payload)
    return {
        "action": "resolve",
        "resolved": unknown_id,
        "count": int(payload["count"]),
    }

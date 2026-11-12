"""Shared analysis helpers used by the CLI and the MCP server."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.evidence.provenance import Provenance

from .disassembler import Disassembler, DisassemblyError, DisassemblyResult
from .functions import discover_functions
from .loader import BinaryInfo, BinaryLoader
from .strings import StringExtractor


class AnalysisError(Exception):
    """Raised when an analysis request cannot be satisfied."""


MAX_DISASSEMBLY_COUNT = 100_000
MAX_STRING_LIMIT = 200_000

#: Ceiling on call-graph nodes embedded in a report (bounded work).
REPORT_MAX_CALLGRAPH_FUNCTIONS = 1000

#: Ceiling on call-graph edges embedded in a report (bounded work).
REPORT_MAX_CALLGRAPH_EDGES = 5000


def load_binary(path: str | Path) -> BinaryInfo:
    """Load a binary and return normalized metadata."""
    return BinaryLoader().load(path)


def read_code(path: str | Path, info: BinaryInfo, address: int, want_bytes: int) -> bytes:
    """Read bytes for ``address``; raise when the address is unmapped."""
    offset = info.va_to_offset(address)
    section = info.section_for_va(address)
    if offset is None or section is None:
        raise AnalysisError(f"address 0x{address:x} is not mapped to file bytes")
    remaining = (section.offset + (section.raw_size or section.size)) - offset
    if remaining <= 0:
        raise AnalysisError(f"address 0x{address:x} has no file bytes")
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(min(want_bytes, remaining))


def resolve_target(info: BinaryInfo, address: int | None, function: str | None) -> int:
    """Resolve the disassembly start from an address, a function name, or the entry point."""
    if address is not None:
        return address
    if function:
        match = next((c for c in discover_functions(info) if c.name == function), None)
        if match is None:
            raise AnalysisError(f"function {function!r} not found")
        return match.address
    if info.entry_point is not None:
        return info.entry_point
    raise AnalysisError("no address supplied and binary has no entry point")


def disassemble_region(
    path: str | Path,
    info: BinaryInfo,
    start: int,
    count: int = 50,
) -> DisassemblyResult:
    """Disassemble ``count`` instructions at ``start`` inside an executable section."""
    if count < 1:
        raise AnalysisError("count must be >= 1")
    if count > MAX_DISASSEMBLY_COUNT:
        raise AnalysisError(f"count too large (limit {MAX_DISASSEMBLY_COUNT})")
    section = info.section_for_va(start)
    if section is None or not section.is_executable:
        raise AnalysisError(f"address 0x{start:x} is not inside an executable section")
    code = read_code(path, info, start, count * 16)
    disassembler = Disassembler(info.architecture, info.bitness, info.endianness)
    return disassembler.disassemble(code, base_address=start, max_instructions=count)


def build_report(
    path: str | Path,
    string_limit: int = 5000,
    include_callgraph: bool = False,
) -> dict[str, Any]:
    """Build the phase 1 JSON report for ``path``.

    The report always contains ``provenance``, ``binary``, ``functions``,
    ``strings`` and ``disassembly``. Nothing more than the file bytes is read and
    nothing is executed.

    Args:
        path: Binary to analyse.
        string_limit: Maximum strings kept under ``report["strings"]``
            (``0 .. MAX_STRING_LIMIT``).
        include_callgraph: When true, a ``"callgraph"`` section holding
            :meth:`~codevanta.analysis.callgraph.CallGraph.to_dict` is added.
            When false the key is omitted entirely, so the payload is unchanged
            for callers that do not ask for a graph.

    Returns:
        The JSON-serializable report.

    Raises:
        AnalysisError: If ``string_limit`` is out of range, or -- when
            ``include_callgraph`` is true -- if the graph cannot be built.

    Note:
        **Layering.** :mod:`codevanta.core.report` is a *core* module and must not
        import :mod:`codevanta.analysis` at import time: that package imports
        :class:`AnalysisError` from here, so a module-level import would create a
        cycle and would also drag the analysis layer into every core consumer.
        The dependency is therefore resolved with a **lazy import of**
        :func:`~codevanta.analysis.callgraph.build_call_graph` **inside this
        function**, executed only when ``include_callgraph`` is true.

    Note:
        **Bounded work.** The embedded graph is capped at
        ``REPORT_MAX_CALLGRAPH_FUNCTIONS`` (1000) nodes and
        ``REPORT_MAX_CALLGRAPH_EDGES`` (5000) edges, which are well below the
        call-graph defaults (:data:`~codevanta.analysis.callgraph.DEFAULT_MAX_FUNCTIONS`
        / ``DEFAULT_MAX_EDGES``) so a report stays a bounded payload. When either
        cap cuts the result short, ``report["callgraph"]["truncated"]`` is true.
        The pre-computed function candidates are reused instead of rediscovering
        them, so the report never scans the binary twice for candidates.
    """
    if string_limit < 0:
        raise AnalysisError("string_limit must be >= 0")
    if string_limit > MAX_STRING_LIMIT:
        raise AnalysisError(f"string_limit too large (limit {MAX_STRING_LIMIT})")
    info = load_binary(path)
    provenance = (
        Provenance()
        .add_step("load_binary")
        .add_step("discover_functions")
        .add_step("extract_strings")
    )
    candidates = discover_functions(info)
    all_strings = StringExtractor(min_length=4).extract(path, info=info)
    kept = all_strings[:string_limit]
    disassembly: dict[str, Any] | None = None
    if info.entry_point is not None:
        try:
            disassembly = disassemble_region(path, info, info.entry_point, count=32).to_dict()
        except (AnalysisError, DisassemblyError):
            disassembly = None
    report: dict[str, Any] = {
        "provenance": provenance.to_dict(),
        "binary": info.to_dict(),
        "functions": [c.to_dict() for c in candidates],
        "strings": {
            "count": len(all_strings),
            "returned": len(kept),
            "truncated": len(kept) < len(all_strings),
            "items": [s.to_dict() for s in kept],
        },
        "disassembly": disassembly,
    }
    if include_callgraph:
        # Lazy import on purpose: core must not import the analysis package at
        # module import time (analysis imports AnalysisError from this module).
        from codevanta.analysis.callgraph import build_call_graph

        graph = build_call_graph(
            path,
            info,
            functions=candidates,
            max_functions=REPORT_MAX_CALLGRAPH_FUNCTIONS,
            max_edges=REPORT_MAX_CALLGRAPH_EDGES,
        )
        report["callgraph"] = graph.to_dict()
    return report

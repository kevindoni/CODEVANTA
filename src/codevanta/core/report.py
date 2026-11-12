"""Shared analysis helpers used by the CLI and the MCP server."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.evidence.provenance import Provenance

from .disassembler import Disassembler, DisassemblyError, DisassemblyResult
from .functions import discover_functions
from .loader import BinaryInfo, BinaryLoader
from .strings import StringExtractor


class AnalysisError(Exception):
    """Raised when an analysis request cannot be satisfied."""


MAX_DISASSEMBLY_COUNT = 100_000
MAX_STRING_LIMIT = 200_000
#: Hard ceiling for ``xref_limit`` (mirrors ``MAX_STRING_LIMIT``).
MAX_XREF_LIMIT = 200_000
#: Cross references kept in the report by default (the scan budget stays at
#: :data:`codevanta.analysis.xrefs.DEFAULT_MAX_BYTES`).
DEFAULT_XREF_LIMIT = 2_000

#: Ceiling on call-graph nodes embedded in a report (bounded work).
REPORT_MAX_CALLGRAPH_FUNCTIONS = 1000

#: Ceiling on call-graph edges embedded in a report (bounded work).
REPORT_MAX_CALLGRAPH_EDGES = 5000

#: Instruction budget for the entry-point CFG embedded in a report (bounded
#: work; the :func:`codevanta.analysis.cfg.build_cfg` default, made explicit so
#: the report cap is visible next to the other section caps).
REPORT_MAX_CFG_INSTRUCTIONS = 2000

#: Block budget for the entry-point CFG embedded in a report (bounded work;
#: likewise the analyzer default).
REPORT_MAX_CFG_BLOCKS = 500


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


def _empty_cfg(address: int | None, warnings: list[str]) -> dict[str, Any]:
    """Build the degraded ``cfg`` payload used when no graph could be produced.

    Mirrors :meth:`codevanta.analysis.cfg.FunctionCFG.to_dict` key for key so
    consumers of the report can rely on one shape; ``warnings`` carries the
    reason the sweep produced nothing.
    """
    evidence = Evidence(
        source="cfg.linear_sweep",
        method="linear_sweep",
        confidence=Confidence.UNKNOWN,
        address=address,
        detail="no blocks; the control-flow graph was not built",
    )
    return {
        "function_address": f"0x{address:x}" if address is not None else None,
        "function_name": None,
        "block_count": 0,
        "instruction_count": 0,
        "truncated": False,
        "warnings": list(warnings),
        "blocks": [],
        "evidence": evidence.to_dict(),
    }


def build_report(
    path: str | Path,
    string_limit: int = 5000,
    xref_limit: int = DEFAULT_XREF_LIMIT,
    include_callgraph: bool = False,
    include_xrefs: bool = False,
    include_cfg: bool = False,
) -> dict[str, Any]:
    """Build the phase 1 JSON report for ``path``.

    The report always contains ``provenance``, ``binary``, ``functions``,
    ``strings`` and ``disassembly``. Nothing more than the file bytes is read and
    nothing is executed.

    The phase 2 engines are additive and opt-in, one section each:
    ``include_xrefs`` adds ``report["xrefs"]``, ``include_cfg`` adds
    ``report["cfg"]`` and ``include_callgraph`` adds ``report["callgraph"]``.
    Without those arguments the payload is exactly the phase 1 report, so no
    existing consumer sees a new key. A requested section whose engine has
    nothing to decode still appears, as a warning-carrying empty result: the
    phase 2 sections never fail the report.

    Args:
        path: Binary to analyse.
        string_limit: Maximum strings kept under ``report["strings"]``
            (``0 .. MAX_STRING_LIMIT``).
        xref_limit: Maximum cross references kept under
            ``report["xrefs"]["items"]`` (``0 .. MAX_XREF_LIMIT``); ``count``
            still reports the true total found by the scan.
        include_callgraph: When true, a ``"callgraph"`` section holding
            :meth:`~codevanta.analysis.callgraph.CallGraph.to_dict` is added.
            When false the key is omitted entirely, so the payload is unchanged
            for callers that do not ask for a graph.
        include_xrefs: When true, an ``"xrefs"`` section with the scan result and
            its evidence is added.
        include_cfg: When true, a ``"cfg"`` section with the entry-point
            control-flow graph is added.

    Returns:
        The JSON-serializable report.

    Raises:
        AnalysisError: If ``string_limit`` or ``xref_limit`` is out of range, or
            -- when ``include_callgraph`` is true -- if the graph cannot be
            built. The phase 2 sections never raise: an engine failure degrades
            to a warning inside that section instead of failing the report.

    Note:
        **Layering.** :mod:`codevanta.core.report` is a *core* module and must not
        import :mod:`codevanta.analysis` at import time: that package imports
        :class:`AnalysisError` from here, so a module-level import would create a
        cycle and would also drag the analysis layer into every core consumer.
        The dependency is therefore resolved with a **lazy import inside this
        function**, executed only when the corresponding section is requested:
        :func:`~codevanta.analysis.callgraph.build_call_graph` for
        ``include_callgraph``, :func:`~codevanta.analysis.xrefs.find_xrefs` for
        ``include_xrefs`` and :func:`~codevanta.analysis.cfg.build_cfg` for
        ``include_cfg``.

    Note:
        **Bounded work.** The embedded graph is capped at
        ``REPORT_MAX_CALLGRAPH_FUNCTIONS`` (1000) nodes and
        ``REPORT_MAX_CALLGRAPH_EDGES`` (5000) edges, which are well below the
        call-graph defaults (:data:`~codevanta.analysis.callgraph.DEFAULT_MAX_FUNCTIONS`
        / ``DEFAULT_MAX_EDGES``) so a report stays a bounded payload. When either
        cap cuts the result short, ``report["callgraph"]["truncated"]`` is true.
        The pre-computed function candidates are reused instead of rediscovering
        them, so the report never scans the binary twice for candidates.

        The requested phase 2 sections are bounded too, and say so in their own
        payloads. The xref scan decodes at most
        :data:`~codevanta.analysis.xrefs.DEFAULT_MAX_BYTES` (4 MB) of executable
        bytes -- a budget cut sets ``report["xrefs"]["scan_truncated"]`` -- and
        only ``xref_limit`` items are embedded, which sets
        ``report["xrefs"]["truncated"]`` the same way the strings section
        reports truncation. The CFG runs with
        ``REPORT_MAX_CFG_INSTRUCTIONS`` (2000) instructions and
        ``REPORT_MAX_CFG_BLOCKS`` (500) blocks, the analyzer's own defaults made
        explicit, and marks ``report["cfg"]["truncated"]`` when either limit cut
        the sweep.
    """
    if string_limit < 0:
        raise AnalysisError("string_limit must be >= 0")
    if string_limit > MAX_STRING_LIMIT:
        raise AnalysisError(f"string_limit too large (limit {MAX_STRING_LIMIT})")
    if xref_limit < 0:
        raise AnalysisError("xref_limit must be >= 0")
    if xref_limit > MAX_XREF_LIMIT:
        raise AnalysisError(f"xref_limit too large (limit {MAX_XREF_LIMIT})")

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
    xrefs_payload: dict[str, Any] | None = None
    cfg_payload: dict[str, Any] | None = None
    if include_xrefs:
        # Lazy import on purpose: core must not import the analysis package at
        # module import time (analysis imports AnalysisError from this module),
        # and a caller that does not want the section pays nothing for it.
        from codevanta.analysis.xrefs import DEFAULT_MAX_BYTES, find_xrefs

        provenance.add_step("find_xrefs")
        # find_xrefs never raises for undecodable input: it reports degraded
        # coverage through warnings (no executable sections, unsupported
        # architecture, unreadable sections) that are passed straight through.
        xref_scan = find_xrefs(path, info, functions=candidates, max_bytes=DEFAULT_MAX_BYTES)
        kept_xrefs = xref_scan.xrefs[:xref_limit]
        xrefs_payload = {
            "count": len(xref_scan.xrefs),
            "returned": len(kept_xrefs),
            "truncated": len(kept_xrefs) < len(xref_scan.xrefs),
            "items": [xref.to_dict() for xref in kept_xrefs],
            "scanned_sections": list(xref_scan.scanned_sections),
            "scanned_bytes": xref_scan.scanned_bytes,
            "scan_truncated": xref_scan.truncated,
            "indirect_skipped": xref_scan.indirect_skipped,
            "warnings": list(xref_scan.warnings),
            "evidence": xref_scan.evidence.to_dict(),
        }
    if include_cfg:
        # Lazy import, same reason as find_xrefs above.
        from codevanta.analysis.cfg import build_cfg

        provenance.add_step("build_cfg")
        if info.entry_point is None:
            cfg_payload = _empty_cfg(None, ["no entry point; control-flow graph not built"])
        else:
            try:
                cfg_payload = build_cfg(
                    path,
                    info,
                    info.entry_point,
                    max_instructions=REPORT_MAX_CFG_INSTRUCTIONS,
                    max_blocks=REPORT_MAX_CFG_BLOCKS,
                ).to_dict()
            except (AnalysisError, DisassemblyError) as exc:
                cfg_payload = _empty_cfg(
                    info.entry_point, [f"control-flow graph not built: {exc}"]
                )

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
    if xrefs_payload is not None:
        report["xrefs"] = xrefs_payload
    if cfg_payload is not None:
        report["cfg"] = cfg_payload
    return report

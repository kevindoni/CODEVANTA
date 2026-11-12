"""Inter-function call graph assembled from resolved call cross references (phase 2).

The graph is an *aggregate* view over the cross references produced by
:mod:`codevanta.analysis.xrefs`. Nothing is disassembled here; this module only
filters, attributes, and deduplicates what the xref scan already proved.

Two rules keep the result honest:

1. **Resolved transfers only.** Exactly three cross-reference kinds become
   edges:

   * ``"call"`` -- a direct call to a literal address. The target is the callee.
   * ``"call_import"`` -- a call through a pointer slot that matches a known
     import. The target is the *slot* address, so the node is an ``import``
     node labelled with the import name and marked ``high`` confidence.
   * ``"call_indirect"`` -- a call through a pointer slot that matches no
     import. The slot address is certain, the callee it holds is not, so the
     target is an ``external`` node of ``unknown`` confidence.

   ``jump`` and ``branch`` references, and indirect calls whose slot address is
   not statically known (``call rax``, ``call qword ptr [rax + 8]``), emit no
   edge -- the xref layer does not report them -- so ``to_dict()`` never
   implies a completeness it does not have.
2. **Caller attribution is a heuristic.** The xref layer records the address of
   the calling *instruction*, not the enclosing function (no function boundary
   data is trusted here). A call site is therefore attributed to the **nearest
   function candidate whose address is at or below the call address inside the
   same section** -- i.e. the candidate that most plausibly owns that address.
   If no candidate exists at or below the call site in that section, the call
   address itself is used as the edge source and a single warning is recorded,
   because the real caller is genuinely unknown. The evidence record of the
   resulting graph states this limitation explicitly.

Addresses are virtual addresses (VA). The analysed file is only ever read from
disk; nothing is loaded or executed, and every loop is bounded by
``max_functions`` / ``max_edges``.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.xrefs import Xref, XrefResult, find_xrefs
from codevanta.core.functions import FunctionCandidate, discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_FUNCTIONS",
    "MAX_LIMIT",
    "CallGraph",
    "CallGraphEdge",
    "CallGraphNode",
    "build_call_graph",
]

#: Largest value accepted for either build limit.
MAX_LIMIT = 200_000

#: Default ceiling on how many function candidates become nodes.
DEFAULT_MAX_FUNCTIONS = 2_000

#: Default ceiling on how many call edges are reported.
DEFAULT_MAX_EDGES = 20_000

#: Xref kind of a direct call to a literal address.
_XREF_CALL = "call"

#: Xref kind of a call through a pointer slot that matched a known import.
_XREF_CALL_IMPORT = "call_import"

#: Xref kind of a call through a resolvable pointer slot with no matching import.
_XREF_CALL_INDIRECT = "call_indirect"

#: Node kinds. ``external`` marks a call target that is not a known candidate
#: and whose callee is unknown; ``import`` marks a pointer slot that matched a
#: known import.
_KIND_ENTRY_POINT = "entry_point"
_KIND_FUNCTION = "function"
_KIND_EXTERNAL = "external"
_KIND_IMPORT = "import"
_KIND_CALL_SITE = "call_site"

#: Cross-reference kinds that become graph edges.
_INCLUDED_XREF_KINDS = frozenset({_XREF_CALL, _XREF_CALL_IMPORT, _XREF_CALL_INDIRECT})

#: Prefix used by :meth:`CallGraph.to_graph_model` node ids for external nodes.
_EXTERNAL_PREFIX = "external:"

#: Prefix used by :meth:`CallGraph.to_graph_model` node ids for import nodes.
_IMPORT_PREFIX = "import:"

#: Fallback id for an address that could not be resolved to any node.
_UNRESOLVED_ID = "unresolved"

#: Evidence describing how the graph as a whole was produced. The label keeps
#: its historical value (``callgraph.direct_calls``) so existing report consumers
#: and snapshots stay stable; the detail text states the extra coverage.
_EVIDENCE_SOURCE = "callgraph.direct_calls"
_EVIDENCE_METHOD = "xref_aggregation"

#: Default label applied to every edge produced by this module.
_EDGE_LABEL = "call"


def _hex(address: int | None) -> str | None:
    """Render ``address`` as lowercase hex, or ``None`` when it is unknown."""
    return None if address is None else f"0x{address:x}"


@dataclass(frozen=True)
class CallGraphNode:
    """One vertex of the call graph.

    Attributes:
        address: Virtual address of the node, or ``None`` when unresolved. For
            an ``import`` node this is the address of the import stub / IAT slot
            the call goes through, not the address of the imported code.
        label: Display name -- the candidate name, the import name, or a
            synthesized ``sub_*`` / ``external_*`` placeholder when no name is
            known.
        kind: ``"entry_point"``, ``"function"``, ``"external"`` or ``"import"``.
        confidence: Confidence value as a plain string, e.g. ``"high"``. Nodes
            for unknown targets always report ``"unknown"``; nodes for resolved
            imports report ``"high"``.
    """

    address: int | None
    label: str
    kind: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the node for the JSON report."""
        return {
            "address": _hex(self.address),
            "label": self.label,
            "kind": self.kind,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class CallGraphEdge:
    """A single directed call edge.

    Attributes:
        source: Attributed caller address, or the call address itself when no
            candidate covers the call site.
        target: Address the call refers to: the callee for a direct call, or the
            pointer slot / import slot for an import or indirect call.
        from_address: Virtual address of the calling instruction.
        label: Edge kind label; ``"call"`` for every edge produced here. Import
            naming is carried by the target node's ``label``, not by the edge.
    """

    source: int | None
    target: int | None
    from_address: int
    label: str = _EDGE_LABEL

    def to_dict(self) -> dict[str, Any]:
        """Serialize the edge for the JSON report."""
        return {
            "source": _hex(self.source),
            "target": _hex(self.target),
            "from_address": _hex(self.from_address),
            "label": self.label,
        }


@dataclass(frozen=True)
class CallGraph:
    """Nodes and call edges for one binary.

    Attributes:
        nodes: Nodes sorted by address (unknown addresses last).
        edges: Edges deduplicated by ``(source, target, from_address)`` and
            sorted by ``(source, from_address)``.
        truncated: ``True`` when a limit or the underlying xref scan cut the
            result short, so the graph may be incomplete.
        evidence: How the graph as a whole was derived.
        warnings: Human-readable caveats; caller-attribution failures are
            reported here exactly once.
    """

    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def _nodes_with_endpoints(self) -> list[CallGraphNode]:
        """Return the nodes plus synthetic nodes for every edge endpoint.

        Caller attribution is heuristic, so an edge can start at a call site that
        is not a candidate, and an indirect target need not be one either. Adding
        a ``call_site`` / ``external`` node for each missing endpoint keeps both
        ``to_dict()`` and ``to_graph_model()`` internally consistent.
        """
        nodes = list(self.nodes)
        known_addresses = {node.address for node in nodes}
        for edge in self.edges:
            for address, kind in (
                (edge.source, _KIND_CALL_SITE),
                (edge.target, _KIND_EXTERNAL),
            ):
                if address in known_addresses:
                    continue
                known_addresses.add(address)
                nodes.append(
                    CallGraphNode(
                        address=address,
                        label=_hex(address) or "unresolved",
                        kind=kind,
                        confidence="unknown",
                    )
                )
        return nodes

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph for the JSON report."""
        nodes = self._nodes_with_endpoints()
        return {
            "node_count": len(nodes),
            "edge_count": len(self.edges),
            "nodes": [node.to_dict() for node in nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

    def to_graph_model(self) -> dict[str, Any]:
        """Serialize the graph as a generic ``{nodes, edges}`` graph model.

        Node ids are strings: ``"0x<addr>"`` for a candidate node,
        ``"import:0x<addr>"`` for a resolved import node and
        ``"external:0x<addr>"`` for a node that only exists because some call
        targeted an address that is not a known candidate. Edge endpoints reuse
        those ids so consumers can join them to the node list.

        Caller attribution is heuristic, so an edge can start at a call site that
        is not a known candidate. Every endpoint without a node gets a synthetic
        node (``call_site`` for a source, ``external`` for a target), so DOT and
        GraphML consumers always see edges that reference existing node ids.
        """
        base_nodes = self._nodes_with_endpoints()
        ids_by_address: dict[int | None, str] = {
            node.address: _node_id(node) for node in base_nodes if node.address is not None
        }
        nodes: list[dict[str, Any]] = [
            {
                "id": _node_id(node),
                "address": _hex(node.address),
                "label": node.label,
                "kind": node.kind,
                "confidence": node.confidence,
            }
            for node in base_nodes
        ]
        known_ids = {node["id"] for node in nodes}

        def ensure_node(endpoint_id: str, address: int | None, kind: str) -> None:
            if endpoint_id in known_ids:
                return
            known_ids.add(endpoint_id)
            nodes.append(
                {
                    "id": endpoint_id,
                    "address": _hex(address),
                    "label": _hex(address) if address is not None else "unresolved",
                    "kind": kind,
                    "confidence": "unknown",
                }
            )

        edges: list[dict[str, Any]] = []
        for edge in self.edges:
            source_id = ids_by_address.get(edge.source, _endpoint_id(edge.source))
            target_id = ids_by_address.get(edge.target, _endpoint_id(edge.target))
            ensure_node(source_id, edge.source, _KIND_CALL_SITE)
            ensure_node(target_id, edge.target, _KIND_EXTERNAL)
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "from_address": _hex(edge.from_address),
                    "label": edge.label,
                }
            )

        nodes.sort(key=lambda node: node["id"])
        edges.sort(key=lambda edge: (edge["source"], edge["target"], edge["from_address"]))
        return {"nodes": nodes, "edges": edges, "truncated": self.truncated}


def _node_id(node: CallGraphNode) -> str:
    """Return the stable graph-model id of ``node``.

    Import nodes are namespaced so a slot address can never be confused with a
    candidate or external node that happens to share the same address.
    """
    if node.address is None:
        return _UNRESOLVED_ID
    if node.kind == _KIND_IMPORT:
        return f"{_IMPORT_PREFIX}0x{node.address:x}"
    if node.kind == _KIND_EXTERNAL:
        return f"{_EXTERNAL_PREFIX}0x{node.address:x}"
    return f"0x{node.address:x}"


def _endpoint_id(address: int | None) -> str:
    """Return a best-effort id for an edge endpoint that has no node."""
    return _UNRESOLVED_ID if address is None else f"0x{address:x}"


def _node_sort_key(node: CallGraphNode) -> tuple[int, int]:
    """Sort nodes by address, pushing unresolved addresses to the end."""
    return (1, 0) if node.address is None else (0, node.address)


def _edge_sort_key(edge: CallGraphEdge) -> tuple[int, int]:
    """Sort edges by attributed caller, then by call site."""
    return (edge.source if edge.source is not None else -1, edge.from_address)


def _validate_limit(name: str, value: int) -> None:
    """Reject limits outside ``1 .. MAX_LIMIT``."""
    if value < 1:
        raise AnalysisError(f"{name} must be >= 1")
    if value > MAX_LIMIT:
        raise AnalysisError(f"{name} too large (limit {MAX_LIMIT})")


def _dedupe_candidates(candidates: list[FunctionCandidate]) -> list[FunctionCandidate]:
    """Keep one candidate per address, preferring the higher confidence.

    Injected candidate lists need not be unique; discovery output usually is. The
    winner is the highest-confidence candidate for an address, with the first
    occurrence breaking ties. The result is sorted by address.
    """
    best: dict[int, FunctionCandidate] = {}
    for candidate in candidates:
        existing = best.get(candidate.address)
        if existing is None or candidate.confidence.score > existing.confidence.score:
            best[candidate.address] = candidate
    return sorted(best.values(), key=lambda candidate: candidate.address)


def _section_key(info: BinaryInfo, address: int) -> tuple[str, int] | None:
    """Identify the section containing ``address`` (``None`` when unmapped)."""
    section = info.section_for_va(address)
    if section is None:
        return None
    return (section.name, section.virtual_address)


def _group_by_section(
    info: BinaryInfo, candidates: list[FunctionCandidate]
) -> dict[tuple[str, int] | None, list[int]]:
    """Map a section key to the ascending candidate addresses inside it."""
    grouped: dict[tuple[str, int] | None, list[int]] = {}
    for candidate in candidates:  # already sorted by address
        grouped.setdefault(_section_key(info, candidate.address), []).append(candidate.address)
    return grouped


def _caller_for(
    grouped: dict[tuple[str, int] | None, list[int]], info: BinaryInfo, address: int
) -> int | None:
    """Return the nearest candidate address at or below ``address``.

    The candidate must live in the same section as ``address`` so that a call is
    never attributed across a section boundary; see the module docstring for why
    this heuristic is used and what it guarantees.
    """
    addresses = grouped.get(_section_key(info, address))
    if not addresses:
        return None
    position = bisect.bisect_right(addresses, address)
    return addresses[position - 1] if position else None


def _target_node(xref: Xref) -> CallGraphNode:
    """Synthesize the node for a call target that is not a known candidate.

    ``call_import`` references name a pointer slot that matched an import, so the
    node is an ``import`` node labelled with the import name (or the slot hex when
    the name is missing) and marked ``high`` confidence: the slot address comes
    straight from the decoded operand and the import table corroborates it.

    Every other included kind (``call`` to an unknown address, ``call_indirect``)
    keeps the historical ``external`` node with ``unknown`` confidence, because
    the callee behind the target is genuinely unknown.
    """
    if xref.kind == _XREF_CALL_IMPORT:
        return CallGraphNode(
            address=xref.to_address,
            label=xref.target_name or f"0x{xref.to_address:x}",
            kind=_KIND_IMPORT,
            confidence=Confidence.HIGH.value,
        )
    return CallGraphNode(
        address=xref.to_address,
        label=f"external_{xref.to_address:x}",
        kind=_KIND_EXTERNAL,
        confidence=Confidence.UNKNOWN.value,
    )


def build_call_graph(
    path: str | Path,
    info: BinaryInfo,
    functions: list[FunctionCandidate] | None = None,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> CallGraph:
    """Build the call graph for ``info``.

    Edges come from ``call``, ``call_import`` and ``call_indirect`` cross
    references; ``jump``/``branch`` references and unresolved indirect calls are
    ignored (see the module docstring).

    Args:
        path: File the bytes are read from (read-only; never executed).
        info: Loaded binary metadata used for section lookups, scanning and
            import matching.
        functions: Pre-computed function candidates. When omitted,
            :func:`~codevanta.core.functions.discover_functions` is used.
        max_functions: Candidate budget (1 .. :data:`MAX_LIMIT`). When more
            candidates exist the lowest-address ones are kept, the rest are
            dropped, and the graph is marked ``truncated``; calls to a dropped
            candidate degrade to ``external`` nodes.
        max_edges: Edge budget (1 .. :data:`MAX_LIMIT`). Edges are deduplicated
            and sorted before the cut, so the kept edges are the first ones in
            ``(source, from_address)`` order.

    Returns:
        The assembled :class:`CallGraph`.

    Raises:
        AnalysisError: If either limit falls outside ``1 .. MAX_LIMIT``.
    """
    _validate_limit("max_functions", max_functions)
    _validate_limit("max_edges", max_edges)

    warnings: list[str] = []
    candidates = _dedupe_candidates(
        list(functions) if functions is not None else discover_functions(info)
    )
    truncated = False
    if len(candidates) > max_functions:
        candidates = candidates[:max_functions]
        truncated = True
        warnings.append(
            f"function limit reached (max_functions={max_functions}); only the "
            "lowest-address candidates are represented"
        )

    nodes: dict[int, CallGraphNode] = {}
    for candidate in candidates:
        is_entry = info.entry_point is not None and candidate.address == info.entry_point
        nodes[candidate.address] = CallGraphNode(
            address=candidate.address,
            label=candidate.name or f"sub_{candidate.address:x}",
            kind=_KIND_ENTRY_POINT if is_entry else _KIND_FUNCTION,
            confidence=candidate.confidence.value,
        )

    grouped = _group_by_section(info, candidates)
    xrefs: XrefResult = find_xrefs(path, info, functions=candidates)
    if xrefs.truncated:
        truncated = True
    warnings.extend(f"xrefs: {warning}" for warning in xrefs.warnings)

    edges: dict[tuple[int | None, int | None, int], tuple[CallGraphEdge, str]] = {}
    unattributed = 0
    for xref in xrefs.xrefs:
        if xref.kind not in _INCLUDED_XREF_KINDS:
            continue  # jumps and conditional branches are never call edges
        target = xref.to_address
        source = _caller_for(grouped, info, xref.from_address)
        if source is None:
            source = xref.from_address
            unattributed += 1
        # A candidate at the target address wins over a synthesized node: the
        # xref scan proves the address, the candidate proves it is code.
        if target not in nodes:
            nodes[target] = _target_node(xref)
        key = (source, target, xref.from_address)
        if key not in edges:
            edges[key] = (
                CallGraphEdge(
                    source=source,
                    target=target,
                    from_address=xref.from_address,
                    label=_EDGE_LABEL,
                ),
                xref.kind,
            )

    ordered = sorted(edges.values(), key=lambda item: _edge_sort_key(item[0]))
    if len(ordered) > max_edges:
        ordered = ordered[:max_edges]
        truncated = True
        warnings.append(f"edge limit reached (max_edges={max_edges}); later edges were dropped")
    ordered_edges = [edge for edge, _kind in ordered]
    import_edges = sum(1 for _edge, kind in ordered if kind == _XREF_CALL_IMPORT)
    indirect_edges = sum(1 for _edge, kind in ordered if kind == _XREF_CALL_INDIRECT)
    if unattributed:
        warnings.append(
            f"caller attribution failed for {unattributed} call site(s); the call "
            "address itself is used as the edge source for those edges"
        )

    ordered_nodes = sorted(nodes.values(), key=_node_sort_key)
    evidence = Evidence(
        source=_EVIDENCE_SOURCE,
        method=_EVIDENCE_METHOD,
        confidence=Confidence.MEDIUM,
        detail=(
            f"{len(ordered_nodes)} nodes and {len(ordered_edges)} edges from direct "
            f"calls plus resolved import and indirect memory calls "
            f"({import_edges} import, {indirect_edges} indirect); caller attribution "
            "is heuristic (nearest candidate at or below the call site) and unresolved "
            "indirect calls are not represented"
        ),
    )
    return CallGraph(
        nodes=ordered_nodes,
        edges=ordered_edges,
        truncated=truncated,
        evidence=evidence,
        warnings=tuple(warnings),
    )

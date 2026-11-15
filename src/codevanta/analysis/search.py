"""Byte-pattern, string, and procedure search plus call-path navigation.

This module is CODEVANTA's in-memory search and navigation lane, the analogue
of a REA-style ``search_bytes`` / ``search_strings`` / ``search_procedures`` /
``trace_call_path`` toolkit. It never touches a file itself: every function
operates on data the caller already holds in memory (raw ``bytes``, a loaded
:class:`~codevanta.core.loader.BinaryInfo`, or a
:class:`~codevanta.analysis.callgraph.CallGraph`), so synthetic-buffer tests
need no fixtures and the MCP layer stays a thin file-reading wrapper.

The four guarantees, in the house style:

* **Typed.** Every result is a frozen dataclass with a JSON-safe ``to_dict()``.
* **Bounded.** Hit/match counts, pattern sizes, text lengths, depths, preview
  windows and subgraph sizes all carry hard caps (``DEFAULT_*`` / ``MAX_*``).
  A cap that fires is reported through ``truncated``, never silently.
* **Honest.** A search over raw bytes is ``certain`` evidence (direct byte
  equality); anything derived from the heuristic call graph (call paths,
  subgraphs) is ``medium``. Nothing is disassembled or executed here.
* **Offline.** No file, network, subprocess or library dependency beyond the
  modules imported below.

Pattern syntax (``search_bytes``)
--------------------------------

``pattern`` is a hex string with optional ``??`` byte wildcards, e.g.
``"8B 44 ?? 24 ?? ??"`` -- whitespace between bytes is allowed and ignored.
``mask`` is an optional per-byte override with the same byte count as the
pattern: ``x`` / ``X`` keep the pattern byte significant, ``?`` ignores it
(equivalent to a wildcard at that position).

Graph sources (``build_call_path`` / ``get_call_graph_subset``)
--------------------------------------------------------------

Both accept either a :class:`~codevanta.analysis.callgraph.CallGraph` (node
labels are used for names) or a bare sequence of
:class:`~codevanta.analysis.callgraph.CallGraphEdge`. Edge endpoints without a
node are rendered as ``sub_<hex>`` placeholders. Edges with an unresolved
endpoint (``None``) are skipped: a caller-attribution failure must not invent
a caller.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from codevanta.analysis.callgraph import CallGraph, CallGraphEdge
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, SectionInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "CONTEXT_RADIUS",
    "DEFAULT_HITS_LIMIT",
    "DEFAULT_MATCH_LIMIT",
    "DEFAULT_PATH_DEPTH",
    "DEFAULT_PREVIEW_BYTES",
    "DEFAULT_SUBSET_DEPTH",
    "GRAPH_DIRECTIONS",
    "MAX_HITS_LIMIT",
    "MAX_MATCH_LIMIT",
    "MAX_PATTERN_BYTES",
    "MAX_PATH_DEPTH",
    "MAX_PREVIEW_BYTES",
    "MAX_SUBSET_DEPTH",
    "MAX_SUBSET_NODES",
    "MAX_TEXT_CHARS",
    "MIN_STRING_CHARS",
    "SEARCH_MODES",
    "CallPath",
    "GraphSubset",
    "NavContext",
    "PathNode",
    "Proc",
    "ProcMatches",
    "SearchHit",
    "SearchHits",
    "StringMatch",
    "StringMatches",
    "SubsetEdge",
    "SubsetNode",
    "build_call_path",
    "get_call_graph_subset",
    "navigate",
    "procedures",
    "search_bytes",
    "search_procedures",
    "search_strings",
]

# ---- limits ----------------------------------------------------------------

#: Hit ceiling when the caller does not pass ``limit`` (byte search).
DEFAULT_HITS_LIMIT = 64

#: Hard ceiling on ``limit`` for the byte search.
MAX_HITS_LIMIT = 4_096

#: Hard ceiling on ``limit`` for the string and procedure searches.
MAX_MATCH_LIMIT = 20_000

#: Match ceiling when the caller does not pass ``limit`` (strings / procs).
DEFAULT_MATCH_LIMIT = 100

#: Hex bytes reported around each byte-search hit (this many on each side).
CONTEXT_RADIUS = 16

#: Hard ceiling on the number of pattern bytes.
MAX_PATTERN_BYTES = 256

#: Characters kept of one matched string (``length`` stays honest).
MAX_TEXT_CHARS = 256

#: Shortest printable run that becomes a searchable string (same rule as
#: :mod:`codevanta.core.strings`).
MIN_STRING_CHARS = 4

#: BFS depth when ``build_call_path`` is not given one.
DEFAULT_PATH_DEPTH = 8

#: Hard ceiling on the call-path depth.
MAX_PATH_DEPTH = 64

#: BFS depth when ``get_call_graph_subset`` is not given one.
DEFAULT_SUBSET_DEPTH = 3

#: Hard ceiling on the subgraph depth.
MAX_SUBSET_DEPTH = 16

#: Hard ceiling on subgraph nodes; exceeding it sets ``truncated``.
MAX_SUBSET_NODES = 10_000

#: Byte-preview size ``navigate`` uses when the caller does not pass one.
DEFAULT_PREVIEW_BYTES = 32

#: Hard ceiling on the ``navigate`` byte preview.
MAX_PREVIEW_BYTES = 256

#: Match strategies accepted by the string and procedure searches.
SEARCH_MODES: tuple[str, ...] = ("literal", "regex")

#: Directions accepted by ``get_call_graph_subset``.
GRAPH_DIRECTIONS: tuple[str, ...] = ("callers", "callees")

#: A procedure inventory: a loaded binary or an explicit ``Proc`` sequence.
ProcSource = BinaryInfo | Sequence["Proc"]

#: A call-graph source: a built graph or a bare edge sequence.
GraphSource = CallGraph | Sequence[CallGraphEdge]


# ---- helpers ---------------------------------------------------------------


def _hex(address: int) -> str:
    """Render ``address`` as lowercase ``0x`` hex."""
    return f"0x{address:x}"


def _check_address(name: str, value: int) -> int:
    """Return ``value`` when it is a non-negative plain integer, else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    if value < 0:
        raise AnalysisError(f"{name} must be non-negative, got {value}")
    return value


def _check_limit(name: str, value: int, maximum: int) -> int:
    """Return ``value`` when it is a plain integer in ``1 .. maximum``, else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{name} must be an integer, got {value!r}")
    if value < 1 or value > maximum:
        raise AnalysisError(f"{name} must be between 1 and {maximum}, got {value}")
    return value


def _check_mode(mode: str) -> str:
    """Return ``mode`` when it is a known match strategy, else raise."""
    if mode not in SEARCH_MODES:
        raise AnalysisError(f"mode must be one of {', '.join(SEARCH_MODES)}, got {mode!r}")
    return mode


def _check_sequence(
    name: str,
    value: Sequence[Any],
    item_type: type[Any],
) -> list[Any]:
    """Return ``value`` as a list when every item is ``item_type``, else raise.

    ``str`` / ``bytes`` are rejected outright: they are sequences of the wrong
    thing, and accepting them would turn a typo into a confusing type error.
    """
    if isinstance(value, (str, bytes, bytearray)):
        raise AnalysisError(
            f"{name} must be a sequence of {item_type.__name__}, got {type(value).__name__}"
        )
    checked: list[Any] = []
    for index, item in enumerate(value):
        if not isinstance(item, item_type):
            raise AnalysisError(
                f"{name}[{index}] must be a {item_type.__name__}, got {type(item).__name__}"
            )
        checked.append(item)
    return checked


# ---- result types ----------------------------------------------------------


@dataclass(frozen=True)
class SearchHit:
    """One byte-pattern match: its offset and the surrounding hex bytes."""

    offset: int
    context: str

    def to_dict(self) -> dict[str, Any]:
        return {"offset": _hex(self.offset), "context": self.context}


@dataclass(frozen=True)
class SearchHits:
    """All matches of one byte-pattern search.

    Attributes:
        hits: First ``limit`` matches in offset order.
        total: Honest number of matches in the scanned window.
        truncated: ``True`` when ``total`` exceeds the reported ``hits``.
        evidence: How the hits were found.
    """

    hits: tuple[SearchHit, ...]
    total: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [hit.to_dict() for hit in self.hits],
            "total": self.total,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class StringMatch:
    """One extracted string that matched the query."""

    offset: int
    text: str
    length: int

    def to_dict(self) -> dict[str, Any]:
        return {"offset": _hex(self.offset), "text": self.text, "length": self.length}


@dataclass(frozen=True)
class StringMatches:
    """All extracted strings that matched one query."""

    matches: tuple[StringMatch, ...]
    total: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": [match.to_dict() for match in self.matches],
            "total": self.total,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class Proc:
    """One procedure of an inventory: address, name, and best-known size."""

    address: int
    name: str
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"address": _hex(self.address), "name": self.name}
        if self.size is not None:
            data["size"] = self.size
        return data


@dataclass(frozen=True)
class ProcMatches:
    """All procedures of one inventory whose name matched the pattern."""

    matches: tuple[Proc, ...]
    total: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": [match.to_dict() for match in self.matches],
            "total": self.total,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class PathNode:
    """One hop of a call path."""

    address: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"address": _hex(self.address), "name": self.name}


@dataclass(frozen=True)
class CallPath:
    """Shortest call path between two procedures of one call graph.

    ``length`` is the number of call edges (``len(path) - 1``); ``found`` is
    ``False`` -- with an empty ``path`` and ``length`` 0 -- when no path within
    ``max_depth`` connects the two addresses.
    """

    path: tuple[PathNode, ...]
    length: int
    found: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": [node.to_dict() for node in self.path],
            "length": self.length,
            "found": self.found,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class SubsetNode:
    """One node of a bounded call-graph subgraph, with its BFS depth."""

    address: int
    name: str
    depth: int

    def to_dict(self) -> dict[str, Any]:
        return {"address": _hex(self.address), "name": self.name, "depth": self.depth}


@dataclass(frozen=True)
class SubsetEdge:
    """One traversed edge of a bounded call-graph subgraph."""

    source: int
    target: int

    def to_dict(self) -> dict[str, Any]:
        return {"source": _hex(self.source), "target": _hex(self.target)}


@dataclass(frozen=True)
class GraphSubset:
    """The bounded neighbourhood of one procedure in a call graph."""

    root: int
    direction: str
    nodes: tuple[SubsetNode, ...]
    edges: tuple[SubsetEdge, ...]
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": _hex(self.root),
            "direction": self.direction,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class NavContext:
    """Navigation context around one address.

    ``containing`` is set only when a procedure provably covers the address: a
    procedure with a known ``size`` must span it, and a size-less procedure is
    assumed to end where the next procedure begins (or at its own start when
    it is the last one). ``preview_offset`` is the file offset the hex preview
    was read from, ``None`` when the address maps to no in-range bytes.
    """

    address: int
    containing: Proc | None
    previous: Proc | None
    next: Proc | None
    section: str | None
    preview_offset: int | None
    preview: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": _hex(self.address),
            "containing": None if self.containing is None else self.containing.to_dict(),
            "previous": None if self.previous is None else self.previous.to_dict(),
            "next": None if self.next is None else self.next.to_dict(),
            "section": self.section,
            "preview_offset": None if self.preview_offset is None else _hex(self.preview_offset),
            "preview": self.preview,
            "evidence": self.evidence.to_dict(),
        }


# ---- byte-pattern search ---------------------------------------------------


def _parse_byte_pattern(pattern: str) -> tuple[int | None, ...]:
    """Parse a hex pattern with ``??`` wildcards into one entry per byte.

    Raises:
        AnalysisError: If ``pattern`` is not a non-empty string of hex byte
            pairs and ``??`` wildcards, or exceeds ``MAX_PATTERN_BYTES``.
    """
    if not isinstance(pattern, str):
        raise AnalysisError(f"pattern must be a string, got {type(pattern).__name__}")
    compact = "".join(pattern.split())
    if not compact:
        raise AnalysisError("pattern must not be empty")
    if len(compact) % 2:
        raise AnalysisError(f"pattern must be whole hex bytes, got {pattern!r}")
    parsed: list[int | None] = []
    for index in range(0, len(compact), 2):
        token = compact[index : index + 2]
        if token == "??":
            parsed.append(None)
            continue
        try:
            parsed.append(int(token, 16))
        except ValueError:
            raise AnalysisError(
                f"pattern byte {index // 2} must be two hex digits or '??', got {token!r}"
            ) from None
    if len(parsed) > MAX_PATTERN_BYTES:
        raise AnalysisError(f"pattern must be at most {MAX_PATTERN_BYTES} bytes")
    return tuple(parsed)


def _apply_mask(
    parsed: tuple[int | None, ...],
    mask: str | None,
) -> tuple[int | None, ...]:
    """Fold the optional per-byte ``mask`` into ``parsed``.

    Mask characters (whitespace ignored) align with the pattern bytes: ``x`` /
    ``X`` keep the pattern byte, ``?`` drops it.
    """
    if mask is None:
        return parsed
    if not isinstance(mask, str):
        raise AnalysisError(f"mask must be a string, got {type(mask).__name__}")
    compact = "".join(mask.split())
    if len(compact) != len(parsed):
        raise AnalysisError(
            f"mask must have one character per pattern byte ({len(parsed)}), got {len(compact)}"
        )
    masked: list[int | None] = []
    for index, (byte, flag) in enumerate(zip(parsed, compact, strict=False)):
        if flag == "?":
            masked.append(None)
        elif flag in ("x", "X"):
            masked.append(byte)
        else:
            raise AnalysisError(f"mask character {index} must be 'x' or '?', got {flag!r}")
    return tuple(masked)


def _matches_at(window: bytes, position: int, parsed: tuple[int | None, ...]) -> bool:
    """Whether ``parsed`` matches ``window`` at ``position``."""
    return all(
        byte is None or window[position + index] == byte for index, byte in enumerate(parsed)
    )


def search_bytes(
    data: bytes,
    pattern: str,
    mask: str | None = None,
    start: int = 0,
    end: int | None = None,
    limit: int = DEFAULT_HITS_LIMIT,
) -> SearchHits:
    """Search ``data`` for a hex byte pattern with ``??`` wildcards.

    Args:
        data: Bytes to scan (a file read once by the caller).
        pattern: Hex byte pattern, e.g. ``"8B 44 ?? 24 ?? ??"``; whitespace
            between bytes is ignored.
        mask: Optional per-byte mask with one ``x`` (match) or ``?`` (ignore)
            character per pattern byte.
        start: First offset of the scanned window (inclusive).
        end: One-past-the-last offset of the scanned window; ``None`` scans to
            the end of ``data``.
        limit: Maximum number of hits reported (``1 .. MAX_HITS_LIMIT``);
            ``total`` keeps counting beyond it.

    Returns:
        A :class:`SearchHits` whose ``hits`` are in offset order, each with a
        hex context of up to ``CONTEXT_RADIUS`` bytes on both sides of the
        match. Evidence source is ``search.bytes`` with ``certain`` confidence.

    Raises:
        AnalysisError: If ``data`` is not ``bytes``, the pattern or mask is
            malformed, the window bounds are inconsistent, or ``limit`` is out
            of range.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise AnalysisError(f"data must be bytes, got {type(data).__name__}")
    parsed = _apply_mask(_parse_byte_pattern(pattern), mask)
    first_byte = next((byte for byte in parsed if byte is not None), None)
    if first_byte is None:
        raise AnalysisError("pattern must contain at least one concrete hex byte")
    begin = _check_address("start", start)
    finish = len(data) if end is None else _check_address("end", end)
    if finish < begin:
        raise AnalysisError(f"end ({finish}) must not be below start ({begin})")
    limit = _check_limit("limit", limit, MAX_HITS_LIMIT)

    window = bytes(data[begin:finish])
    span = len(parsed)
    total = 0
    hits: list[SearchHit] = []
    position = window.find(first_byte)
    while position != -1:
        if position + span > len(window):
            break
        if _matches_at(window, position, parsed):
            total += 1
            if len(hits) < limit:
                hits.append(
                    SearchHit(
                        offset=begin + position,
                        context=window[
                            max(0, position - CONTEXT_RADIUS) : position + span + CONTEXT_RADIUS
                        ].hex(),
                    )
                )
        position = window.find(first_byte, position + 1)
    evidence = Evidence(
        source="search.bytes",
        method="hex_pattern_scan",
        confidence=Confidence.CERTAIN,
        address=begin,
        detail=(
            f"{total} match(es) for a {span}-byte pattern in {len(window)} "
            f"byte(s); {len(hits)} reported"
        ),
    )
    return SearchHits(
        hits=tuple(hits),
        total=total,
        truncated=total > len(hits),
        evidence=evidence,
    )


# ---- string search ---------------------------------------------------------

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_CHARS)
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_CHARS)


def _extract_strings(data: bytes) -> list[tuple[int, str]]:
    """Extract printable ASCII and UTF-16LE runs, in offset order.

    The same two scans and the same ``MIN_STRING_CHARS`` minimum as
    :class:`codevanta.core.strings.StringExtractor`, applied to in-memory
    bytes so this module never needs a file.
    """
    found: list[tuple[int, str]] = [
        (match.start(), match.group().decode("ascii", errors="replace"))
        for match in _ASCII_RUN.finditer(data)
    ]
    found.extend(
        (match.start(), match.group().decode("utf-16-le", errors="replace"))
        for match in _UTF16LE_RUN.finditer(data)
    )
    found.sort(key=lambda item: (item[0], item[1]))
    return found


def search_strings(
    data: bytes,
    query: str,
    mode: str = "literal",
    case_sensitive: bool = True,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> StringMatches:
    """Search the printable strings extracted from ``data`` for ``query``.

    Strings are the same bounded ASCII and UTF-16LE runs
    :mod:`codevanta.core.strings` extracts (at least ``MIN_STRING_CHARS``
    printable characters). ``mode="literal"`` is a substring test,
    ``mode="regex"`` applies ``query`` with :func:`re.search` per string.

    Args:
        data: Bytes to extract strings from.
        query: Literal substring or regular expression; empty queries are
            rejected because they would match every string.
        mode: ``"literal"`` or ``"regex"``.
        case_sensitive: Literal comparisons and regex matching honour it.
        limit: Maximum matches reported (``1 .. MAX_MATCH_LIMIT``); ``total``
            keeps counting beyond it.

    Returns:
        A :class:`StringMatches` in offset order. ``text`` is capped at
        ``MAX_TEXT_CHARS`` while ``length`` stays the honest string length.
        Evidence source is ``search.strings``, ``certain``.

    Raises:
        AnalysisError: If ``data`` is not ``bytes``, ``query`` is empty,
            ``mode`` is unknown, the regex is invalid, or ``limit`` is out of
            range.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise AnalysisError(f"data must be bytes, got {type(data).__name__}")
    if not isinstance(query, str) or not query.strip():
        raise AnalysisError("query must be a non-empty string")
    _check_mode(mode)
    limit = _check_limit("limit", limit, MAX_MATCH_LIMIT)

    try:
        expression = re.compile(query) if case_sensitive else re.compile(query, re.IGNORECASE)
    except re.error as exc:
        raise AnalysisError(f"invalid regex: {exc}") from None

    total = 0
    matches: list[StringMatch] = []
    for offset, text in _extract_strings(bytes(data)):
        if mode == "regex":
            hit = expression.search(text) is not None
        elif case_sensitive:
            hit = query in text
        else:
            hit = query.lower() in text.lower()
        if not hit:
            continue
        total += 1
        if len(matches) < limit:
            matches.append(StringMatch(offset=offset, text=text[:MAX_TEXT_CHARS], length=len(text)))
    evidence = Evidence(
        source="search.strings",
        method=f"{mode}_string_match",
        confidence=Confidence.CERTAIN,
        detail=(
            f"{total} matching string(s) among printable runs of at least "
            f"{MIN_STRING_CHARS} chars; {len(matches)} reported"
        ),
    )
    return StringMatches(
        matches=tuple(matches),
        total=total,
        truncated=total > len(matches),
        evidence=evidence,
    )


# ---- procedure search ------------------------------------------------------


def procedures(info: BinaryInfo) -> tuple[Proc, ...]:
    """Build the procedure inventory of a loaded binary.

    Every function candidate of
    :func:`codevanta.core.functions.discover_functions` becomes a
    :class:`Proc`; candidates without a symbol name get the usual
    ``sub_<hex>`` placeholder and keep their best-known ``size`` (which may be
    ``None``).
    """
    return tuple(
        sorted(
            (
                Proc(
                    address=candidate.address,
                    name=candidate.name or f"sub_{candidate.address:x}",
                    size=candidate.size,
                )
                for candidate in discover_functions(info)
            ),
            key=lambda proc: proc.address,
        )
    )


def _procedure_inventory(data: ProcSource) -> list[Proc]:
    """Normalise the ``search_procedures`` inventory argument."""
    if isinstance(data, BinaryInfo):
        return list(procedures(data))
    return _check_sequence("data", data, Proc)


def search_procedures(
    data: ProcSource,
    pattern: str,
    mode: str = "literal",
    limit: int = DEFAULT_MATCH_LIMIT,
) -> ProcMatches:
    """Search procedure names for ``pattern``.

    Args:
        data: The inventory to search -- a loaded
            :class:`~codevanta.core.loader.BinaryInfo` (its function
            candidates are used) or a sequence of :class:`Proc` records.
        pattern: Literal substring or regular expression matched against each
            name; matching is case-sensitive.
        mode: ``"literal"`` or ``"regex"``.
        limit: Maximum matches reported (``1 .. MAX_MATCH_LIMIT``); ``total``
            keeps counting beyond it.

    Returns:
        A :class:`ProcMatches` in address order. The match over the given
        inventory is exact (``certain``), but each name is only as trustworthy
        as its own discovery evidence. Evidence source is ``search.procs``.

    Raises:
        AnalysisError: If ``data`` is neither a ``BinaryInfo`` nor a ``Proc``
            sequence, ``pattern`` is empty or not a string, ``mode`` is
            unknown, the regex is invalid, or ``limit`` is out of range.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        raise AnalysisError("pattern must be a non-empty string")
    _check_mode(mode)
    limit = _check_limit("limit", limit, MAX_MATCH_LIMIT)

    try:
        expression = re.compile(pattern) if mode == "regex" else None
    except re.error as exc:
        raise AnalysisError(f"invalid regex: {exc}") from None

    inventory = sorted(_procedure_inventory(data), key=lambda proc: proc.address)
    total = 0
    matches: list[Proc] = []
    for proc in inventory:
        if expression is not None:
            hit = expression.search(proc.name) is not None
        else:
            hit = pattern in proc.name
        if not hit:
            continue
        total += 1
        if len(matches) < limit:
            matches.append(proc)
    evidence = Evidence(
        source="search.procs",
        method=f"{mode}_name_match",
        confidence=Confidence.CERTAIN,
        detail=(
            f"{total} of {len(inventory)} procedure name(s) matched; "
            f"{len(matches)} reported; each name is only as trustworthy as "
            "its own discovery evidence"
        ),
    )
    return ProcMatches(
        matches=tuple(matches),
        total=total,
        truncated=total > len(matches),
        evidence=evidence,
    )


# ---- call-graph navigation -------------------------------------------------


def _graph_model(inventory: GraphSource) -> tuple[list[CallGraphEdge], dict[int, str]]:
    """Normalise a graph source into its edge list and address-to-name map."""
    if isinstance(inventory, CallGraph):
        names = {node.address: node.label for node in inventory.nodes if node.address is not None}
        return list(inventory.edges), names
    return _check_sequence("inventory", inventory, CallGraphEdge), {}


def _adjacency(edges: Sequence[CallGraphEdge]) -> dict[int, list[int]]:
    """Forward adjacency ``caller -> [callees]``; unresolved ends are dropped."""
    forward: dict[int, list[int]] = {}
    for edge in edges:
        if edge.source is None or edge.target is None:
            continue
        forward.setdefault(edge.source, []).append(edge.target)
    return forward


def _path_evidence(hops: int, found: bool) -> Evidence:
    """Evidence record for one call-path result."""
    return Evidence(
        source="search.callpath",
        method="bfs_callgraph",
        confidence=Confidence.MEDIUM,
        detail=(
            f"shortest path of {hops} call edge(s); caller attribution in the graph is heuristic"
            if found
            else "no path within the depth budget; the graph may also be "
            "incomplete (truncated xref scans)"
        ),
    )


def build_call_path(
    inventory: GraphSource,
    start_addr: int,
    goal_addr: int,
    max_depth: int = DEFAULT_PATH_DEPTH,
) -> CallPath:
    """BFS the shortest call path between two addresses of one call graph.

    Args:
        inventory: A :class:`~codevanta.analysis.callgraph.CallGraph` or a
            bare sequence of its edges.
        start_addr: Address the path starts at (a graph node).
        goal_addr: Address the path must reach (a graph node).
        max_depth: Longest accepted path in edges (``1 .. MAX_PATH_DEPTH``).

    Returns:
        A :class:`CallPath`. ``found`` is ``True`` with ``length`` call edges
        when a path exists within ``max_depth``; equal start and goal that are
        graph nodes give a one-node path of length 0. A missing endpoint or a
        graph that cannot connect them returns ``found=False`` with an empty
        path -- never an error. Evidence source is ``search.callpath``,
        ``medium`` (the underlying edges are heuristically attributed).

    Raises:
        AnalysisError: If an address or ``max_depth`` is out of range, or the
            inventory is neither a ``CallGraph`` nor an edge sequence.
    """
    _check_address("start_addr", start_addr)
    _check_address("goal_addr", goal_addr)
    _check_limit("max_depth", max_depth, MAX_PATH_DEPTH)
    edges, names = _graph_model(inventory)
    forward = _adjacency(edges)
    known = set(forward)
    for edge in edges:
        if edge.target is not None:
            known.add(edge.target)

    if start_addr not in known or goal_addr not in known:
        return CallPath(path=(), length=0, found=False, evidence=_path_evidence(0, False))
    if start_addr == goal_addr:
        node = PathNode(address=start_addr, name=names.get(start_addr, f"sub_{start_addr:x}"))
        return CallPath(path=(node,), length=0, found=True, evidence=_path_evidence(0, True))

    parents: dict[int, int] = {start_addr: start_addr}
    depths: dict[int, int] = {start_addr: 0}
    queue: deque[int] = deque([start_addr])
    found = False
    while queue and not found:
        current = queue.popleft()
        if depths[current] >= max_depth:
            continue
        for target in forward.get(current, ()):
            if target in parents:
                continue
            parents[target] = current
            depths[target] = depths[current] + 1
            if target == goal_addr:
                found = True
                break
            queue.append(target)
    if not found:
        return CallPath(path=(), length=0, found=False, evidence=_path_evidence(0, False))

    path: list[int] = [goal_addr]
    while path[-1] != start_addr:
        path.append(parents[path[-1]])
    path.reverse()
    hops = len(path) - 1
    return CallPath(
        path=tuple(
            PathNode(address=address, name=names.get(address, f"sub_{address:x}"))
            for address in path
        ),
        length=hops,
        found=True,
        evidence=_path_evidence(hops, True),
    )


def get_call_graph_subset(
    data: GraphSource,
    address: int,
    direction: str = "callers",
    max_depth: int = DEFAULT_SUBSET_DEPTH,
) -> GraphSubset:
    """Collect the bounded call-graph neighbourhood of one address.

    Args:
        data: A :class:`~codevanta.analysis.callgraph.CallGraph` or a bare
            sequence of its edges.
        address: Root address of the subgraph.
        direction: ``"callers"`` walks incoming edges towards the callers,
            ``"callees"`` walks outgoing edges towards the callees.
        max_depth: BFS depth (``1 .. MAX_SUBSET_DEPTH``). When more than
            ``MAX_SUBSET_NODES`` distinct nodes would be collected, the walk
            stops and ``truncated`` reports it.

    Returns:
        A :class:`GraphSubset` whose ``nodes`` carry their BFS depth (the root
        is depth 0) and whose ``edges`` are exactly the graph edges between
        collected nodes. An address without edges in the requested direction
        gives an empty subset -- an isolated address is not an error.
        Evidence source is ``search.graph_subset``, ``medium``.

    Raises:
        AnalysisError: If ``address`` or ``max_depth`` is out of range,
            ``direction`` is unknown, or the graph source is invalid.
    """
    _check_address("address", address)
    if direction not in GRAPH_DIRECTIONS:
        raise AnalysisError(
            f"direction must be one of {', '.join(GRAPH_DIRECTIONS)}, got {direction!r}"
        )
    _check_limit("max_depth", max_depth, MAX_SUBSET_DEPTH)
    edges, names = _graph_model(data)

    adjacency: dict[int, list[int]] = {}
    traversed: dict[tuple[int, int], tuple[int, int]] = {}
    for edge in edges:
        if edge.source is None or edge.target is None:
            continue
        if direction == "callees":
            source, target = edge.source, edge.target
        else:
            source, target = edge.target, edge.source
        adjacency.setdefault(source, []).append(target)
        traversed.setdefault((edge.source, edge.target), (edge.source, edge.target))

    nodes: list[SubsetNode] = []
    placed: set[int] = set()
    truncated = False
    if address in adjacency:
        depths: dict[int, int] = {address: 0}
        queue: deque[int] = deque([address])
        while queue:
            if len(placed) >= MAX_SUBSET_NODES:
                truncated = True
                break
            current = queue.popleft()
            placed.add(current)
            nodes.append(
                SubsetNode(
                    address=current,
                    name=names.get(current, f"sub_{current:x}"),
                    depth=depths[current],
                )
            )
            if depths[current] >= max_depth:
                continue
            for target in adjacency.get(current, ()):
                if target not in depths:
                    depths[target] = depths[current] + 1
                    queue.append(target)

    subset_edges = tuple(
        SubsetEdge(source=source, target=target)
        for source, target in sorted(traversed.values())
        if source in placed and target in placed
    )
    evidence = Evidence(
        source="search.graph_subset",
        method="bfs_subgraph",
        confidence=Confidence.MEDIUM,
        detail=(
            f"{len(nodes)} node(s) and {len(subset_edges)} edge(s) within "
            f"{max_depth} step(s) towards the {direction} of {_hex(address)}; "
            "caller attribution in the graph is heuristic"
        ),
    )
    return GraphSubset(
        root=address,
        direction=direction,
        nodes=tuple(nodes),
        edges=subset_edges,
        truncated=truncated,
        evidence=evidence,
    )


# ---- navigation context ----------------------------------------------------


def _mapped_size(section: SectionInfo) -> int:
    """Bytes of ``section`` that are actually present in the file."""
    return section.raw_size if section.raw_size > 0 else section.size


def _containing(procs: Sequence[Proc], address: int) -> Proc | None:
    """The procedure covering ``address``, or ``None``.

    A known ``size`` must span the address; a size-less procedure is assumed
    to end where the next procedure begins (or to cover only its own start
    when it is the last one).
    """
    for index, proc in enumerate(procs):
        if proc.address > address:
            break
        if proc.size is not None:
            if address < proc.address + proc.size:
                return proc
            continue
        nxt = procs[index + 1].address if index + 1 < len(procs) else proc.address + 1
        if address < nxt:
            return proc
    return None


def _neighbours(
    procs: Sequence[Proc],
    address: int,
    containing: Proc | None,
) -> tuple[Proc | None, Proc | None]:
    """Nearest previous and next procedures around ``address``.

    When a procedure contains the address both neighbours are relative to that
    procedure's start; otherwise they are relative to the address itself.
    """
    anchor = containing.address if containing is not None else address
    previous: Proc | None = None
    following: Proc | None = None
    for proc in procs:
        if proc.address < anchor:
            previous = proc
        elif proc.address > anchor and following is None:
            following = proc
    return previous, following


def _preview(
    data: bytes,
    address: int,
    sections: Sequence[SectionInfo],
    preview: int,
) -> tuple[int | None, str]:
    """Hex preview of up to ``preview`` bytes at ``address``.

    With a covering section the virtual address is mapped through the section
    file offset (bounded by the section's mapped size); without one the buffer
    is treated as flat (address == file offset). An address that maps outside
    ``data`` yields ``(None, "")``.
    """
    section: SectionInfo | None = None
    for candidate in sections:
        if (
            candidate.size > 0
            and candidate.virtual_address <= address
            and address < candidate.virtual_address + candidate.size
        ):
            section = candidate
            break
    if section is not None:
        offset = section.offset + (address - section.virtual_address)
        in_section = section.virtual_address + _mapped_size(section) - address
        take = min(preview, in_section, len(data) - offset)
    else:
        offset = address
        take = min(preview, len(data) - address)
    if offset < 0 or take <= 0:
        return None, ""
    return offset, bytes(data[offset : offset + take]).hex()


def navigate(
    data: bytes,
    address: int,
    procs: Sequence[Proc] = (),
    sections: Sequence[SectionInfo] = (),
    preview: int = DEFAULT_PREVIEW_BYTES,
) -> NavContext:
    """Build the navigation context around one address in ``data``.

    Args:
        data: File bytes the caller already read.
        address: Virtual address to describe.
        procs: Procedure inventory (see :func:`procedures` to build one from a
            loaded binary).
        sections: Section metadata used for the section name, the file-offset
            mapping and the preview bounds.
        preview: Byte-preview size (``1 .. MAX_PREVIEW_BYTES``).

    Returns:
        A :class:`NavContext` with the containing procedure, the nearest
        previous/next procedures, the covering section's name, and the hex
        byte preview. Evidence source is ``search.navigate``, ``medium`` (the
        byte preview is direct file bytes; the procedure neighbourhood comes
        from the inventory's own, possibly heuristic, evidence).

    Raises:
        AnalysisError: If ``data`` is not ``bytes``, an inventory item has the
            wrong type, ``address`` is negative, or ``preview`` is out of
            range.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise AnalysisError(f"data must be bytes, got {type(data).__name__}")
    _check_address("address", address)
    preview = _check_limit("preview", preview, MAX_PREVIEW_BYTES)
    ordered = sorted(_check_sequence("procs", procs, Proc), key=lambda proc: proc.address)
    checked_sections = _check_sequence("sections", sections, SectionInfo)

    containing = _containing(ordered, address)
    previous, following = _neighbours(ordered, address, containing)
    section: str | None = None
    for candidate in checked_sections:
        if (
            candidate.size > 0
            and candidate.virtual_address <= address
            and address < candidate.virtual_address + candidate.size
        ):
            section = candidate.name
            break
    offset, preview_hex = _preview(bytes(data), address, checked_sections, preview)
    evidence = Evidence(
        source="search.navigate",
        method="context_window",
        confidence=Confidence.MEDIUM,
        address=address,
        detail=(
            f"containing={containing.name if containing else None} "
            f"section={section} preview={len(preview_hex) // 2} byte(s)"
        ),
    )
    return NavContext(
        address=address,
        containing=containing,
        previous=previous,
        next=following,
        section=section,
        preview_offset=offset,
        preview=preview_hex,
        evidence=evidence,
    )

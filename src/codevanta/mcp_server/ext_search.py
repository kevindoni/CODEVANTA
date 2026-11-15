"""MCP tools for the binary search and navigation lane (no MCP imports).

Six tools over :mod:`codevanta.analysis.search`:

* ``codevanta_search_bytes`` -- hex byte-pattern search with ``??`` wildcards.
* ``codevanta_search_strings`` -- query the extracted printable strings.
* ``codevanta_search_procs`` -- query the function-name inventory.
* ``codevanta_call_path`` -- BFS shortest call path between two addresses.
* ``codevanta_navigate`` -- containing/prev/next function, section, byte
  preview around one address.
* ``codevanta_graph_subset`` -- bounded callers/callees subgraph.

The registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import search
from codevanta.analysis.callgraph import CallGraph, build_call_graph
from codevanta.core.functions import discover_functions
from codevanta.core.report import AnalysisError, load_binary

__all__ = [
    "MAX_DATA_BYTES",
    "codevanta_call_path",
    "codevanta_graph_subset",
    "codevanta_navigate",
    "codevanta_search_bytes",
    "codevanta_search_procs",
    "codevanta_search_strings",
]

#: Hard ceiling on the bytes one search call reads from a file (64 MiB), the
#: same budget the cross-reference scan uses.
MAX_DATA_BYTES = 64_000_000

#: Function-candidate cap for the graphs the path/subset tools build, the
#: same default the ``codevanta_callgraph`` tool publishes.
_GRAPH_MAX_FUNCTIONS = 1_000

#: Edge cap for those graphs (also ``codevanta_callgraph``'s default).
_GRAPH_MAX_EDGES = 5_000


def _validate_path(path: str) -> Path:
    """Return ``path`` as an existing regular file, or raise naming it."""
    if not isinstance(path, str) or not path.strip():
        raise AnalysisError("path must be a non-empty string")
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def _read_data(path: Path) -> bytes:
    """Read the whole file, bounded by :data:`MAX_DATA_BYTES`."""
    payload = path.read_bytes()
    if len(payload) > MAX_DATA_BYTES:
        raise AnalysisError(
            f"file is {len(payload)} bytes; the search lane reads at most "
            f"{MAX_DATA_BYTES} bytes per call"
        )
    return payload


def _graph_for(path: Path) -> CallGraph:
    """Build the bounded call graph of ``path`` for path/subset tools."""
    info = load_binary(path)
    return build_call_graph(
        path,
        info,
        functions=discover_functions(info),
        max_functions=_GRAPH_MAX_FUNCTIONS,
        max_edges=_GRAPH_MAX_EDGES,
    )


def codevanta_search_bytes(
    path: str,
    pattern: str,
    mask: str | None = None,
    start: int = 0,
    end: int | None = None,
    limit: int = search.DEFAULT_HITS_LIMIT,
) -> dict[str, Any]:
    """Search the file's raw bytes for a hex pattern with ``??`` wildcards.

    Certain confidence: direct byte equality over the file bytes. ``start`` /
    ``end`` bound the scanned window; ``mask`` overrides pattern bytes with
    ``x`` (match) or ``?`` (ignore). Bounded read of ``MAX_DATA_BYTES``.
    """
    data = _read_data(_validate_path(path))
    return search.search_bytes(
        data, pattern, mask=mask, start=start, end=end, limit=limit
    ).to_dict()


def codevanta_search_strings(
    path: str,
    query: str,
    mode: str = "literal",
    case_sensitive: bool = True,
    limit: int = search.DEFAULT_MATCH_LIMIT,
) -> dict[str, Any]:
    """Search the file's printable ASCII / UTF-16LE strings for ``query``.

    ``mode="literal"`` is a substring test, ``mode="regex"`` a per-string
    ``re.search``. Certain confidence over the extracted strings; offsets are
    file offsets. Bounded read of ``MAX_DATA_BYTES``.
    """
    data = _read_data(_validate_path(path))
    return search.search_strings(
        data, query, mode=mode, case_sensitive=case_sensitive, limit=limit
    ).to_dict()


def codevanta_search_procs(
    path: str,
    pattern: str,
    mode: str = "literal",
    limit: int = search.DEFAULT_MATCH_LIMIT,
) -> dict[str, Any]:
    """Search function names (symbols, exports, entry point) for ``pattern``.

    The inventory comes from the structural function discovery lane; every
    match carries ``address``, ``name`` and best-known ``size``. Matching is
    case-sensitive literal substring or regex.
    """
    target = _validate_path(path)
    procs = search.procedures(load_binary(target))
    return search.search_procedures(procs, pattern, mode=mode, limit=limit).to_dict()


def codevanta_call_path(
    path: str,
    start_addr: int,
    goal_addr: int,
    max_depth: int = search.DEFAULT_PATH_DEPTH,
) -> dict[str, Any]:
    """BFS the shortest call path between two addresses.

    The graph is built with the same direct-call / resolved-import edges as
    ``codevanta_callgraph`` (bounded to 1000 candidates / 5000 edges), so a
    ``found`` path is medium confidence: caller attribution is heuristic.
    Missing endpoints or a disconnected graph return ``found=false``.
    """
    target = _validate_path(path)
    return search.build_call_path(
        _graph_for(target), start_addr, goal_addr, max_depth=max_depth
    ).to_dict()


def codevanta_navigate(
    path: str,
    address: int,
    preview: int = search.DEFAULT_PREVIEW_BYTES,
) -> dict[str, Any]:
    """Describe one address: containing / previous / next function, section
    name, and a hex byte preview mapped through the section file offset."""
    target = _validate_path(path)
    info = load_binary(target)
    return search.navigate(
        _read_data(target),
        address,
        procs=search.procedures(info),
        sections=info.sections,
        preview=preview,
    ).to_dict()


def codevanta_graph_subset(
    path: str,
    address: int,
    direction: str = "callers",
    max_depth: int = search.DEFAULT_SUBSET_DEPTH,
) -> dict[str, Any]:
    """Collect the bounded callers or callees neighbourhood of one address.

    Nodes carry their BFS depth from ``address`` (depth 0); ``truncated``
    reports a node-cap cut. Medium confidence, heuristic graph edges.
    """
    target = _validate_path(path)
    return search.get_call_graph_subset(
        _graph_for(target), address, direction=direction, max_depth=max_depth
    ).to_dict()

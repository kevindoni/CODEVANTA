"""Standalone DOT and GraphML export for CODEVANTA's plain-dict graph model.

The exporters here are deliberately dependency free: they import only the
standard library and know nothing about CODEVANTA's analysis classes.  Any
producer that can describe a graph as

.. code-block:: python

    {
        "nodes": [{"id": "0x401000", "label": "main", "kind": "entry_point"}],
        "edges": [{"source": "0x401000", "target": "0x401040", "label": "call"}],
    }

can therefore render it through :func:`to_dot` or :func:`to_graphml` — the call
graph, the control-flow graph, and future viewers all share one renderer.

Contract
--------
* ``nodes`` items: ``id`` (required, non-blank ``str``, unique), ``label``
  (required ``str``), ``kind`` (optional ``str``).
* ``edges`` items: ``source`` and ``target`` (required, must be existing node
  ids), ``label`` (optional ``str``, defaults to ``"call"``).
* Size is bounded by ``max_nodes`` / ``max_edges``, both ``>= 1``.
* Anything that violates the contract raises :class:`GraphExportError`; a
  partially valid graph is never rendered.

Both exporters are deterministic: nodes are emitted sorted by ``id`` and edges
sorted by ``(source, target, label)``, so two graphs with the same content but a
different insertion order produce identical output.

Graph content is only ever *rendered* — nothing is executed or written to disk;
callers decide whether to persist the returned string.

Limitations
-----------
* DOT output escapes ``"``, ``\\``, newline, carriage return and tab, and
  replaces other C0 control characters with ``U+FFFD``.  It does not implement
  the full DOT grammar for record/HTML-like labels.
* GraphML stores node ids in ``id`` attributes; XML attribute-value
  normalization turns tab/newline characters inside an id into spaces, so such
  ids do not round-trip byte-exactly (labels still do).
* No layout is emitted (no coordinates): renderers run their own layout engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree

__all__ = [
    "DEFAULT_EDGE_LABEL",
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_NODES",
    "DEFAULT_TITLE",
    "GraphExportError",
    "to_dot",
    "to_graphml",
]

#: Title used when the caller does not pass one.
DEFAULT_TITLE = "CODEVANTA graph"

#: Node budget per export; keeps output bounded for very large graphs.
DEFAULT_MAX_NODES = 5000

#: Edge budget per export.
DEFAULT_MAX_EDGES = 20000

#: Label rendered for an edge that carries no explicit label.
DEFAULT_EDGE_LABEL = "call"

#: Node ``kind`` values drawn as rectangles; everything else is an ellipse.
_BOX_KINDS = frozenset({"function", "entry_point"})

#: GraphML namespace and schema location declared on the root element.
_GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
_GRAPHML_SCHEMA = "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"

#: ``key`` ids used by the GraphML ``data`` elements.
_KEY_NODE_LABEL = "d0"
_KEY_NODE_KIND = "d1"
_KEY_EDGE_LABEL = "d2"

#: Characters escaped inside DOT double-quoted strings.
_DOT_SPECIAL_RE = re.compile(r'[\\"\n\r\t]')
_DOT_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}

#: Characters that are not representable in XML 1.0 (or in a lone surrogate).
_ILLEGAL_TEXT_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")

#: Replacement for characters that cannot be represented at all.
_REPLACEMENT_CHAR = "\ufffd"


class GraphExportError(ValueError):
    """Raised when a graph cannot be rendered in the requested format."""


@dataclass(frozen=True)
class _Node:
    """A validated graph node."""

    id: str
    label: str
    kind: str


@dataclass(frozen=True)
class _Edge:
    """A validated graph edge; ``label`` always holds a non-blank label."""

    source: str
    target: str
    label: str


def _check_limit(value: Any, name: str) -> int:
    """Return ``value`` as an export limit, or raise :class:`GraphExportError`."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise GraphExportError(f"{name} must be an int, got {type(value).__name__}")
    if value < 1:
        raise GraphExportError(f"{name} must be >= 1, got {value}")
    return value


def _check_title(title: Any) -> str:
    """Return a usable title, falling back to :data:`DEFAULT_TITLE` when blank."""
    if not isinstance(title, str):
        raise GraphExportError(f"title must be a str, got {type(title).__name__}")
    return title if title.strip() else DEFAULT_TITLE


def _check_sequence(graph: dict[str, Any], key: str) -> list[Any]:
    """Return ``graph[key]`` as a list, or raise :class:`GraphExportError`."""
    if key not in graph:
        raise GraphExportError(f"graph is missing required key {key!r}")
    value = graph[key]
    if not isinstance(value, list):
        raise GraphExportError(f"graph[{key!r}] must be a list, got {type(value).__name__}")
    return value


def _require_text(item: dict[str, Any], key: str, context: str) -> str:
    """Return ``item[key]`` as a string, or raise :class:`GraphExportError`."""
    if key not in item:
        raise GraphExportError(f"{context}: missing required key {key!r}")
    value = item[key]
    if not isinstance(value, str):
        raise GraphExportError(f"{context}: {key!r} must be a str, got {type(value).__name__}")
    return value


def _require_id(item: dict[str, Any], key: str, context: str) -> str:
    """Return a non-blank identifier, or raise :class:`GraphExportError`."""
    value = _require_text(item, key, context)
    if not value.strip():
        raise GraphExportError(f"{context}: {key!r} must not be blank")
    return value


def _optional_text(item: dict[str, Any], key: str, context: str, default: str) -> str:
    """Return an optional string field, using ``default`` when absent or ``None``."""
    value = item.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise GraphExportError(f"{context}: {key!r} must be a str, got {type(value).__name__}")
    return value


def _check_mapping(value: Any, context: str) -> dict[str, Any]:
    """Return ``value`` as a mapping, or raise :class:`GraphExportError`."""
    if not isinstance(value, dict):
        raise GraphExportError(f"{context} must be a dict, got {type(value).__name__}")
    return value


def _parse_node(raw: Any, index: int) -> _Node:
    """Validate one raw node entry."""
    context = f"node {index}"
    item = _check_mapping(raw, context)
    node_id = _require_id(item, "id", context)
    label = _require_text(item, "label", context)
    kind = _optional_text(item, "kind", context, "")
    return _Node(id=node_id, label=label, kind=kind)


def _parse_edge(raw: Any, index: int, node_ids: dict[str, _Node]) -> _Edge:
    """Validate one raw edge entry and resolve both of its endpoints."""
    context = f"edge {index}"
    item = _check_mapping(raw, context)
    source = _require_id(item, "source", context)
    target = _require_id(item, "target", context)
    if source not in node_ids:
        raise GraphExportError(f"{context}: source {source!r} is not a known node id")
    if target not in node_ids:
        raise GraphExportError(f"{context}: target {target!r} is not a known node id")
    label = _optional_text(item, "label", context, DEFAULT_EDGE_LABEL)
    if not label.strip():
        label = DEFAULT_EDGE_LABEL
    return _Edge(source=source, target=target, label=label)


def _parse_graph(
    graph: Any,
    max_nodes: Any,
    max_edges: Any,
) -> tuple[list[_Node], list[_Edge]]:
    """Validate the whole graph and return deterministically ordered nodes/edges."""
    if not isinstance(graph, dict):
        raise GraphExportError(f"graph must be a dict, got {type(graph).__name__}")
    node_limit = _check_limit(max_nodes, "max_nodes")
    edge_limit = _check_limit(max_edges, "max_edges")

    raw_nodes = _check_sequence(graph, "nodes")
    raw_edges = _check_sequence(graph, "edges")

    if len(raw_nodes) > node_limit:
        raise GraphExportError(f"graph has {len(raw_nodes)} nodes, max_nodes is {node_limit}")
    if len(raw_edges) > edge_limit:
        raise GraphExportError(f"graph has {len(raw_edges)} edges, max_edges is {edge_limit}")

    nodes: list[_Node] = []
    node_ids: dict[str, _Node] = {}
    for index, raw in enumerate(raw_nodes):
        node = _parse_node(raw, index)
        if node.id in node_ids:
            raise GraphExportError(f"node {index}: duplicate node id {node.id!r}")
        node_ids[node.id] = node
        nodes.append(node)

    edges = [_parse_edge(raw, index, node_ids) for index, raw in enumerate(raw_edges)]

    nodes.sort(key=lambda node: node.id)
    edges.sort(key=lambda edge: (edge.source, edge.target, edge.label))
    return nodes, edges


def _sanitize(value: str) -> str:
    """Replace characters that cannot be represented in output with ``U+FFFD``."""
    return _ILLEGAL_TEXT_RE.sub(_REPLACEMENT_CHAR, value)


def _display_label(label: str, node_id: str) -> str:
    """Return the label to render, falling back to the node id when blank."""
    return label if label.strip() else node_id


def _dot_quote(value: str) -> str:
    """Return ``value`` as a double-quoted, escaped DOT string."""
    escaped = _DOT_SPECIAL_RE.sub(lambda match: _DOT_ESCAPES[match.group(0)], _sanitize(value))
    return f'"{escaped}"'


def _dot_shape(kind: str) -> str:
    """Return the DOT shape for a node ``kind``."""
    return "box" if kind.strip().lower() in _BOX_KINDS else "ellipse"


def to_dot(
    graph: dict[str, Any],
    title: str = DEFAULT_TITLE,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> str:
    """Render ``graph`` as a Graphviz DOT ``digraph``.

    Node ids and labels are emitted as double-quoted, escaped strings; nodes are
    drawn as ``box`` when their ``kind`` is ``"function"`` or ``"entry_point"``
    and as ``ellipse`` otherwise.  Edges always carry a label, defaulting to
    ``"call"``.

    Args:
        graph: Mapping with ``"nodes"`` and ``"edges"`` lists (see module docs).
        title: Graph title; blank titles fall back to :data:`DEFAULT_TITLE`.
        max_nodes: Maximum number of nodes to accept (``>= 1``).
        max_edges: Maximum number of edges to accept (``>= 1``).

    Returns:
        A newline-terminated DOT document.

    Raises:
        GraphExportError: If the graph or any limit violates the contract.
    """
    nodes, edges = _parse_graph(graph, max_nodes, max_edges)
    heading = _dot_quote(_check_title(title))

    lines = [f"digraph {heading} {{", f"  graph [label={heading}];"]
    for node in nodes:
        label = _dot_quote(_display_label(node.label, node.id))
        lines.append(f"  {_dot_quote(node.id)} [label={label}, shape={_dot_shape(node.kind)}];")

    for edge in edges:
        lines.append(
            f"  {_dot_quote(edge.source)} -> {_dot_quote(edge.target)}"
            f" [label={_dot_quote(edge.label)}];"
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def _append_graphml_key(parent: ElementTree.Element, key_id: str, target: str, name: str) -> None:
    """Append one GraphML ``key`` declaration for a string attribute."""
    key = ElementTree.SubElement(parent, "key")
    key.set("id", key_id)
    key.set("for", target)
    key.set("attr.name", name)
    key.set("attr.type", "string")


def _append_graphml_data(parent: ElementTree.Element, key_id: str, text: str) -> None:
    """Append one GraphML ``data`` element carrying ``text``."""
    data = ElementTree.SubElement(parent, "data")
    data.set("key", key_id)
    data.text = _sanitize(text)


def to_graphml(
    graph: dict[str, Any],
    title: str = DEFAULT_TITLE,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> str:
    """Render ``graph`` as a valid GraphML 1.0 document.

    The document declares ``key`` elements for the node ``label``, the node
    ``kind`` and the edge ``label`` attributes, a directed ``graph`` element,
    and a ``desc`` element holding the title.

    Args:
        graph: Mapping with ``"nodes"`` and ``"edges"`` lists (see module docs).
        title: Graph title; blank titles fall back to :data:`DEFAULT_TITLE`.
        max_nodes: Maximum number of nodes to accept (``>= 1``).
        max_edges: Maximum number of edges to accept (``>= 1``).

    Returns:
        An XML declaration followed by the serialized GraphML document.

    Raises:
        GraphExportError: If the graph or any limit violates the contract.
    """
    nodes, edges = _parse_graph(graph, max_nodes, max_edges)
    heading = _check_title(title)

    root = ElementTree.Element("graphml")
    root.set("xmlns", _GRAPHML_NS)
    root.set("xmlns:xsi", _XSI_NS)
    root.set("xsi:schemaLocation", f"{_GRAPHML_NS} {_GRAPHML_SCHEMA}")

    _append_graphml_key(root, _KEY_NODE_LABEL, "node", "label")
    _append_graphml_key(root, _KEY_NODE_KIND, "node", "kind")
    _append_graphml_key(root, _KEY_EDGE_LABEL, "edge", "label")

    graph_element = ElementTree.SubElement(root, "graph")
    graph_element.set("id", "G")
    graph_element.set("edgedefault", "directed")

    description = ElementTree.SubElement(graph_element, "desc")
    description.text = _sanitize(heading)

    for node in nodes:
        element = ElementTree.SubElement(graph_element, "node")
        element.set("id", _sanitize(node.id))
        _append_graphml_data(element, _KEY_NODE_LABEL, _display_label(node.label, node.id))
        if node.kind.strip():
            _append_graphml_data(element, _KEY_NODE_KIND, node.kind)

    for edge in edges:
        element = ElementTree.SubElement(graph_element, "edge")
        element.set("source", _sanitize(edge.source))
        element.set("target", _sanitize(edge.target))
        _append_graphml_data(element, _KEY_EDGE_LABEL, edge.label)

    ElementTree.indent(root, space="  ")
    body = ElementTree.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'

"""Self-contained HTML5 + inline SVG viewer for CODEVANTA's plain-dict graph model.

The viewer turns the same mapping that :mod:`codevanta.analysis.graph_export`
renders to DOT and GraphML into a single, standalone ``.html`` string: no
external CSS, no JavaScript libraries, no web fonts, no CDN and no ``http(s)``
reference of any kind.  A caller can drop the returned text into a file and open
it in any modern browser — offline, air-gapped, from a USB stick.

Contract
--------
* The graph is validated and normalized by
  :func:`codevanta.analysis.graph_export.validate_graph`, so the accepted shape
  and every error message are identical to the DOT/GraphML exporters (see that
  module's docstring).
* Nodes are laid out in three SVG columns chosen by ``kind``:

  ========================================== =========
  ``kind``                                   column
  ========================================== =========
  ``function``, ``entry_point``              left
  ``call_site``                              middle
  ``import``, ``external``, anything else    right
  ========================================== =========

* Ordering is deterministic: nodes are sorted by ``(column, kind rank, id)`` and
  edges by ``(source, target, label)``, so identical content always produces
  byte-identical HTML regardless of input order.
* Node labels, kinds, ids, edge endpoints, the title and the edge table are all
  escaped with :func:`html.escape`; the embedded JSON payload escapes ``"</"`` as
  ``"<\\/"`` so no data can terminate the surrounding ``script`` element.

Nothing is executed and nothing is written to disk: the graph is only rendered.

Limitations
-----------
* Layout is a simple three-column stack.  Edge routing is a straight line between
  the box borders, so dense graphs (and edges inside one column) overlap; there
  is no crossing minimization and no zoom/pan.
* Labels longer than :data:`_LABEL_LIMIT` characters are truncated with an
  ellipsis for display only — the embedded JSON payload keeps the full text.
* The ``<svg>`` element deliberately omits ``xmlns`` (which would be an ``http``
  reference); it is correct when inlined in HTML5, but the fragment is not a
  standalone ``.svg`` file.
* Control characters and lone surrogates in graph text are replaced with
  ``U+FFFD`` before rendering, so the document is always valid UTF-8.
* Very large graphs stay linear in output size but become visually unreadable; the
  ``max_nodes`` / ``max_edges`` budget, not the layout, is the real safeguard.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any

from codevanta.analysis.graph_export import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    DEFAULT_TITLE,
    GraphExportError,
    sanitize_text,
    validate_graph,
)

__all__ = ["to_html"]

#: Box geometry, in SVG user units.  Fixed values keep the output byte-stable.
_BOX_WIDTH = 220
_BOX_HEIGHT = 40
_COLUMN_GAP = 120
_ROW_GAP = 24
_MARGIN = 40

#: Height of the band reserved at the top of the SVG for the column titles.
_COLUMN_HEADER = 28

#: Number of layout columns; index 0, 1 and 2 are left, middle and right.
_COLUMN_COUNT = 3

#: Heading rendered above each column, in column order.
_COLUMN_TITLES = (
    "function / entry_point",
    "call_site",
    "import / external / other",
)

#: ``kind`` values routed to the left column.
_LEFT_KINDS = frozenset({"function", "entry_point"})

#: ``kind`` value routed to the middle column.
_MIDDLE_KIND = "call_site"

#: Tie-breaker rank inside a column; unknown kinds sort last.
_KIND_RANK: dict[str, int] = {
    "entry_point": 0,
    "function": 1,
    "call_site": 2,
    "import": 3,
    "external": 4,
}
_UNKNOWN_KIND_RANK = 9

#: Maximum number of characters of a label drawn inside a node box.
_LABEL_LIMIT = 34

#: Identifier of the SVG arrow marker referenced by every edge line.
_ARROW_ID = "arrow"

#: Inline stylesheet; contains no external reference.
_STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  background: #0f1420;
  color: #e6edf6;
  font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, Arial, sans-serif;
}
header { margin-bottom: 18px; }
h1 { margin: 0 0 6px; font-size: 20px; font-weight: 600; }
.counts { margin: 0; font-size: 13px; color: #9fb0c6; }
.counts span { margin-right: 16px; }
.graph {
  display: block;
  width: 100%;
  height: auto;
  background: #131a29;
  border: 1px solid #223049;
  border-radius: 10px;
}
.column-title { fill: #7f93ad; font-size: 12px; letter-spacing: .04em; text-anchor: middle; }
.edge { fill: none; stroke: #46597a; stroke-width: 1.4; }
#arrow path { fill: #46597a; }
.node rect { fill: #1b2740; stroke: #33496b; stroke-width: 1.2; }
.node.col-0 rect { fill: #1d3352; stroke: #4f8bd4; }
.node.col-1 rect { fill: #1f3040; stroke: #5ba8a0; }
.node.col-2 rect { fill: #2a2438; stroke: #9d7bd8; }
.node text { fill: #e6edf6; text-anchor: middle; }
.node-label { font-size: 13px; }
.node-kind { font-size: 10px; fill: #9fb0c6; }
.empty { fill: #7f93ad; font-size: 13px; text-anchor: middle; }
details {
  margin-top: 18px;
  padding: 10px 14px;
  background: #131a29;
  border: 1px solid #223049;
  border-radius: 10px;
}
summary { cursor: pointer; font-size: 13px; color: #9fb0c6; }
table { width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 12px; }
th, td { padding: 5px 8px; text-align: left; border-bottom: 1px solid #1e2a3e; }
th { font-weight: 600; color: #8ea2bb; }
td { color: #cfdae7; }
""".strip()


@dataclass(frozen=True)
class _Box:
    """Position of one node box on the SVG canvas."""

    x: int
    y: int
    column: int

    @property
    def center_x(self) -> int:
        """Return the horizontal centre of the box."""
        return self.x + _BOX_WIDTH // 2

    @property
    def center_y(self) -> int:
        """Return the vertical centre of the box."""
        return self.y + _BOX_HEIGHT // 2


def _escape(value: str) -> str:
    """Sanitize and escape ``value`` for HTML/XML text and attribute positions."""
    return html.escape(sanitize_text(value), quote=True)


def _check_title(title: Any) -> str:
    """Return a usable page title, falling back to :data:`DEFAULT_TITLE` when blank."""
    if not isinstance(title, str):
        raise GraphExportError(f"title must be a str, got {type(title).__name__}")
    return title if title.strip() else DEFAULT_TITLE


def _kind_key(kind: str) -> str:
    """Return the lower-cased, stripped form of a node ``kind``."""
    return kind.strip().lower()


def _column_index(kind: str) -> int:
    """Return the layout column (0, 1 or 2) for a node ``kind``."""
    key = _kind_key(kind)
    if key in _LEFT_KINDS:
        return 0
    if key == _MIDDLE_KIND:
        return 1
    return 2


def _kind_rank(kind: str) -> int:
    """Return the deterministic in-column ordering rank for a node ``kind``."""
    return _KIND_RANK.get(_kind_key(kind), _UNKNOWN_KIND_RANK)


def _ordered_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return ``nodes`` sorted by ``(column, kind rank, id)``."""
    return sorted(
        nodes,
        key=lambda node: (_column_index(node["kind"]), _kind_rank(node["kind"]), node["id"]),
    )


def _truncate(value: str, limit: int = _LABEL_LIMIT) -> str:
    """Shorten ``value`` to ``limit`` characters, marking the cut with an ellipsis."""
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "\u2026"


def _display_label(node: dict[str, Any]) -> str:
    """Return the label drawn in a box, falling back to the node id when blank."""
    label = node["label"]
    return label if label.strip() else node["id"]


def _layout(nodes: list[dict[str, Any]]) -> tuple[dict[str, _Box], dict[int, int]]:
    """Assign a box position to every node and count the rows used per column."""
    rows: dict[int, int] = dict.fromkeys(range(_COLUMN_COUNT), 0)
    boxes: dict[str, _Box] = {}
    for node in nodes:
        column = _column_index(node["kind"])
        row = rows[column]
        rows[column] = row + 1
        boxes[node["id"]] = _Box(
            x=_MARGIN + column * (_BOX_WIDTH + _COLUMN_GAP),
            y=_MARGIN + _COLUMN_HEADER + row * (_BOX_HEIGHT + _ROW_GAP),
            column=column,
        )
    return boxes, rows


def _canvas_width() -> int:
    """Return the fixed SVG canvas width in user units."""
    return 2 * _MARGIN + _COLUMN_COUNT * _BOX_WIDTH + (_COLUMN_COUNT - 1) * _COLUMN_GAP


def _canvas_height(rows: dict[int, int]) -> int:
    """Return the SVG canvas height needed for the tallest column."""
    tallest = max(rows.values(), default=0)
    content = tallest * (_BOX_HEIGHT + _ROW_GAP) - _ROW_GAP if tallest else 0
    return _MARGIN + _COLUMN_HEADER + content + _MARGIN


def _plural(count: int, noun: str) -> str:
    """Render ``count`` together with a naively pluralized ``noun``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _render_head(heading: str) -> list[str]:
    """Return the document prologue, ending right after ``</head>``."""
    return [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_escape(heading)}</title>",
        f"<style>\n{_STYLE}\n</style>",
        "</head>",
    ]


def _render_header(heading: str, node_count: int, edge_count: int) -> list[str]:
    """Return ``<body>`` plus the header block with the node/edge counts."""
    return [
        "<body>",
        "<header>",
        f"<h1>{_escape(heading)}</h1>",
        '<p class="counts">',
        f'<span class="nodes">{_plural(node_count, "node")}</span>',
        f'<span class="edges">{_plural(edge_count, "edge")}</span>',
        "</p>",
        "</header>",
    ]


def _render_defs() -> list[str]:
    """Return the ``defs`` block declaring the edge arrow marker."""
    return [
        "<defs>",
        f'<marker id="{_ARROW_ID}" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
        '<path d="M0,0 L10,5 L0,10 z"/>',
        "</marker>",
        "</defs>",
    ]


def _edge_anchors(source: _Box, target: _Box) -> tuple[int, int]:
    """Return the x coordinates where an edge leaves ``source`` and meets ``target``."""
    if target.x > source.x:
        return source.x + _BOX_WIDTH, target.x
    if target.x < source.x:
        return source.x, target.x + _BOX_WIDTH
    return source.x + _BOX_WIDTH, target.x + _BOX_WIDTH


def _render_edges(edges: list[dict[str, Any]], boxes: dict[str, _Box]) -> list[str]:
    """Return the ``g`` group holding one arrowed line per edge."""
    parts = ['<g class="edges">']
    for edge in edges:
        source = boxes[edge["source"]]
        target = boxes[edge["target"]]
        x1, x2 = _edge_anchors(source, target)
        tooltip = _escape(f"{edge['source']} -> {edge['target']} ({edge['label']})")
        parts.append(
            f'<line class="edge" x1="{x1}" y1="{source.center_y}" x2="{x2}" '
            f'y2="{target.center_y}" marker-end="url(#{_ARROW_ID})">'
            f"<title>{tooltip}</title></line>"
        )
    parts.append("</g>")
    return parts


def _render_nodes(nodes: list[dict[str, Any]], boxes: dict[str, _Box]) -> list[str]:
    """Return the ``g`` group holding one labelled box per node."""
    parts = ['<g class="nodes">']
    for node in nodes:
        box = boxes[node["id"]]
        label = _escape(_truncate(_display_label(node)))
        kind = node["kind"].strip()
        parts.append(f'<g class="node col-{box.column}">')
        parts.append(f"<title>{_escape(node['id'])}</title>")
        parts.append(
            f'<rect x="{box.x}" y="{box.y}" width="{_BOX_WIDTH}" height="{_BOX_HEIGHT}" rx="6"/>'
        )
        parts.append(f'<text class="node-label" x="{box.center_x}" y="{box.y + 17}">{label}</text>')
        if kind:
            kind_y = box.y + 31
            parts.append(
                f'<text class="node-kind" x="{box.center_x}" y="{kind_y}">{_escape(kind)}</text>'
            )
        parts.append("</g>")
    parts.append("</g>")
    return parts


def _render_svg(
    edges: list[dict[str, Any]],
    nodes: list[dict[str, Any]],
    boxes: dict[str, _Box],
    rows: dict[int, int],
) -> list[str]:
    """Return the complete inline ``<svg>`` element."""
    width = _canvas_width()
    height = _canvas_height(rows)
    parts = [
        f'<svg class="graph" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" aria-label="Graph of nodes and edges">'
    ]
    parts.extend(_render_defs())
    for column, column_title in enumerate(_COLUMN_TITLES):
        x = _MARGIN + column * (_BOX_WIDTH + _COLUMN_GAP) + _BOX_WIDTH // 2
        parts.append(
            f'<text class="column-title" x="{x}" y="{_MARGIN + 16}">{_escape(column_title)}</text>'
        )
    parts.extend(_render_edges(edges, boxes))
    parts.extend(_render_nodes(nodes, boxes))
    if not nodes:
        empty_y = _MARGIN + _COLUMN_HEADER + 20
        parts.append(
            f'<text class="empty" x="{width // 2}" y="{empty_y}">no nodes to display</text>'
        )
    parts.append("</svg>")
    return parts


def _render_edge_table(edges: list[dict[str, Any]]) -> list[str]:
    """Return the collapsible ``details`` block listing every edge."""
    parts = [
        '<details class="edges">',
        f"<summary>Edges ({len(edges)})</summary>",
        "<table>",
        "<thead><tr><th>#</th><th>source</th><th>target</th><th>label</th></tr></thead>",
        "<tbody>",
    ]
    if not edges:
        parts.append('<tr><td colspan="4">no edges</td></tr>')
    for index, edge in enumerate(edges, start=1):
        parts.append(
            f"<tr><td>{index}</td><td>{_escape(edge['source'])}</td>"
            f"<td>{_escape(edge['target'])}</td><td>{_escape(edge['label'])}</td></tr>"
        )
    parts.extend(["</tbody>", "</table>", "</details>"])
    return parts


def _json_payload(validated: dict[str, Any], heading: str) -> str:
    """Return the normalized graph as compact JSON with ``"</"`` defanged."""
    payload = json.dumps(
        {"title": heading, "nodes": validated["nodes"], "edges": validated["edges"]},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return payload.replace("</", "<\\/")


def _render_payload(validated: dict[str, Any], heading: str) -> list[str]:
    """Return the ``application/json`` script element carrying the raw graph."""
    return [
        '<script type="application/json" id="codevanta-graph">',
        _json_payload(validated, heading),
        "</script>",
    ]


def to_html(
    graph: Any,
    title: str = DEFAULT_TITLE,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> str:
    """Render ``graph`` as a self-contained HTML5 document with an inline SVG view.

    The document holds the escaped title and node/edge counts in a header, a
    three-column SVG (function/entry_point, call_site, everything else) with
    labelled node boxes and arrowed edges, a collapsible table listing every edge
    and an ``application/json`` payload with the normalized graph.

    Args:
        graph: Mapping with ``"nodes"`` and ``"edges"`` lists (see
            :mod:`codevanta.analysis.graph_export`).
        title: Page title; blank titles fall back to :data:`DEFAULT_TITLE`.
        max_nodes: Maximum number of nodes to accept (``>= 1``).
        max_edges: Maximum number of edges to accept (``>= 1``).

    Returns:
        A newline-terminated HTML5 document that references no external resource.

    Raises:
        GraphExportError: If the graph, the title or any limit violates the
            contract.
    """
    validated = validate_graph(graph, max_nodes, max_edges)
    heading = _check_title(title)
    nodes = _ordered_nodes(validated["nodes"])
    boxes, rows = _layout(nodes)

    parts = _render_head(heading)
    parts.extend(_render_header(heading, len(nodes), len(validated["edges"])))
    parts.extend(_render_svg(validated["edges"], nodes, boxes, rows))
    parts.extend(_render_edge_table(validated["edges"]))
    parts.extend(_render_payload(validated, heading))
    parts.extend(["</body>", "</html>"])
    return "\n".join(parts) + "\n"

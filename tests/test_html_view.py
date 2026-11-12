"""Tests for the self-contained HTML5 + inline SVG graph viewer.

The tests build plain-dict graphs inline and assert on the returned document as
text; nothing is written to disk and no browser is involved.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

from codevanta.analysis import html_view
from codevanta.analysis.graph_export import DEFAULT_TITLE, GraphExportError
from codevanta.analysis.html_view import to_html

#: Opening tag of the embedded JSON payload.
_JSON_OPEN = '<script type="application/json" id="codevanta-graph">'

#: Opening tag of the single inline behaviour script (it carries no attributes).
_SCRIPT_OPEN = "<script>"


def _graph(nodes: list[dict], edges: list[dict]) -> dict:
    """Build a graph mapping from node/edge lists."""
    return {"nodes": nodes, "edges": edges}


def _sample_graph() -> dict:
    """Return a small three-node, two-edge graph spanning all three columns."""
    return _graph(
        [
            {"id": "a", "label": "main", "kind": "entry_point"},
            {"id": "b", "label": "parse", "kind": "function"},
            {"id": "c", "label": "internal.helper", "kind": "external"},
        ],
        [
            {"source": "a", "target": "b", "label": "call"},
            {"source": "b", "target": "c"},
        ],
    )


def _payload(document: str) -> dict:
    """Parse the embedded JSON payload back into a mapping."""
    start = document.index(_JSON_OPEN) + len(_JSON_OPEN)
    body = document[start : document.index("</script>", start)].strip()
    return json.loads(body.replace("<\\/", "</"))


def _behaviour_script(document: str) -> str:
    """Return the body of the single inline behaviour script."""
    start = document.index(_SCRIPT_OPEN) + len(_SCRIPT_OPEN)
    return document[start : document.index("</script>", start)]


# --------------------------------------------------------------------------- #
# Document structure
# --------------------------------------------------------------------------- #


def test_document_is_html5_with_inline_style_and_svg() -> None:
    """The output is a complete HTML5 document with inline CSS and inline SVG."""
    document = to_html(_sample_graph())

    assert document.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in document
    assert '<meta charset="utf-8">' in document
    assert "<title>CODEVANTA graph</title>" in document
    assert "<style>" in document and "</style>" in document
    assert "<svg" in document and "</svg>" in document
    assert "<body>" in document
    assert document.rstrip().endswith("</html>")


def test_output_references_no_external_resource() -> None:
    """Nothing in the document points outside of itself."""
    lowered = to_html(_sample_graph()).lower()

    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "//cdn" not in lowered
    assert "@import" not in lowered
    assert "<link" not in lowered
    assert 'src="' not in lowered
    assert 'href="' not in lowered


def test_svg_omits_the_external_xmlns_namespace() -> None:
    """The SVG namespace declaration (an http URL) must not be emitted."""
    assert "xmlns" not in to_html(_sample_graph())


def test_special_characters_are_escaped() -> None:
    """Node labels and ids are HTML-escaped in the rendered text."""
    document = to_html(_graph([{"id": "<i>", "label": '<x&"'}], []))

    assert "&lt;x&amp;&quot;" in document
    assert '<x&"' not in document
    assert "<title>&lt;i&gt;</title>" in document
    assert "<title><i></title>" not in document


def test_every_significant_character_is_escaped_in_labels() -> None:
    """``<``, ``>``, ``&`` and ``"`` all leave the label as a safe text node."""
    document = to_html(_graph([{"id": "n", "label": '<a> & "b"</a>'}], []))

    assert "&lt;a&gt; &amp; &quot;b&quot;&lt;/a&gt;" in document
    assert '<a> & "b"' not in document
    assert "</a>" not in document
    assert _payload(document)["nodes"][0]["label"] == '<a> & "b"</a>'


def test_kind_attributes_are_escaped_too() -> None:
    """The ``data-kind`` attribute value is escaped like every other attribute."""
    document = to_html(_graph([{"id": "n", "label": "n", "kind": 'a"<b>'}], []))

    assert 'data-kind="a&quot;&lt;b&gt;"' in document
    assert 'data-kind="a"<b>' not in document


def test_title_is_escaped_and_defaults_when_blank() -> None:
    """The title is escaped in the head and the header, blank titles fall back."""
    document = to_html(_sample_graph(), title='A <b> & "c"')

    assert "<title>A &lt;b&gt; &amp; &quot;c&quot;</title>" in document
    assert "<h1>A &lt;b&gt; &amp; &quot;c&quot;</h1>" in document
    assert "<h1>A <b>" not in document
    assert DEFAULT_TITLE in to_html(_sample_graph(), title="   ")

    with pytest.raises(GraphExportError, match="title must be a str"):
        to_html(_sample_graph(), title=7)


def test_header_reports_counts() -> None:
    """The header shows the node and edge totals, singularized when needed."""
    document = to_html(_sample_graph())

    assert "3 nodes" in document
    assert "2 edges" in document

    single = to_html(_graph([{"id": "a", "label": "main"}], []))
    assert "1 node" in single
    assert "0 edges" in single


def test_empty_graph_still_renders_a_document() -> None:
    """An empty graph yields a valid document with an empty-state message."""
    document = to_html(_graph([], []))

    assert document.startswith("<!DOCTYPE html>")
    assert "<svg" in document and "</svg>" in document
    assert "0 nodes" in document
    assert "0 edges" in document
    assert "no nodes to display" in document
    assert "no edges" in document
    assert '<line class="edge"' not in document


# --------------------------------------------------------------------------- #
# Interaction toolbar and inline behaviour script
# --------------------------------------------------------------------------- #


def test_toolbar_sits_above_the_svg_with_a_search_box() -> None:
    """The toolbar precedes the canvas and carries the search input."""
    document = to_html(_sample_graph())

    assert 'class="toolbar"' in document
    assert 'id="cv-search"' in document
    assert 'type="search"' in document
    assert 'placeholder="search labels"' in document
    assert document.index('class="toolbar"') < document.index("<svg")
    assert document.index('id="cv-search"') < document.index("<svg")


def test_toolbar_renders_one_checkbox_per_kind_group() -> None:
    """Three checked ``cv-kind`` checkboxes map kinds onto filter groups."""
    document = to_html(_sample_graph())

    assert document.count('class="cv-kind"') == 3
    assert document.count('type="checkbox"') == 3
    for kind in ("function", "call_site", "import"):
        assert f'data-kind="{kind}"' in document
    assert document.count("checked>") == 3
    assert "function / entry_point" in document
    assert "import / external" in document


def test_node_groups_expose_their_kind_for_filtering() -> None:
    """Every node group carries the normalized ``kind`` it is filtered by."""
    document = to_html(_sample_graph())

    assert 'class="node col-0" data-kind="entry_point"' in document
    assert 'class="node col-0" data-kind="function"' in document
    # Three node groups plus three filter checkboxes.
    assert document.count('data-kind="') == 6


def test_node_kinds_are_normalized_before_filtering() -> None:
    """Case and padding in ``kind`` cannot leak into the filter attribute."""
    document = to_html(_graph([{"id": "a", "label": "a", "kind": " Function "}], []))

    assert 'data-kind="function"' in document
    assert 'data-kind=" Function "' not in document


def test_single_inline_script_without_src() -> None:
    """Exactly one behavioural script ships, and it is inline."""
    document = to_html(_sample_graph())
    script = _behaviour_script(document)

    assert document.count("<script") == 2  # payload + behaviour
    assert document.count(_SCRIPT_OPEN) == 1
    assert document.count("</script>") == 2
    assert '<script src' not in document.lower()
    assert "src=" not in script
    assert "href=" not in script
    assert script.strip().startswith("(function ()")
    assert document.index(_SCRIPT_OPEN) > document.index('id="codevanta-graph"')


def test_behaviour_script_implements_pan_zoom_search_and_filtering() -> None:
    """The inline script implements the four advertised interactions."""
    script = _behaviour_script(to_html(_sample_graph()))

    # Panning drags the SVG viewBox.
    assert "viewBox" in script
    assert "mousedown" in script and "mousemove" in script
    assert "mouseup" in script
    # Wheel zoom, clamped to the documented range.
    assert "wheel" in script
    assert "MIN_ZOOM = 0.2" in script
    assert "MAX_ZOOM = 8" in script
    assert "Math.min(MAX_ZOOM, Math.max(MIN_ZOOM" in script
    # Search highlights matches and dims the rest.
    assert 'getElementById("cv-search")' in script
    assert "cv-hit" in script and "cv-dim" in script
    # Checkbox filtering reads the node's kind.
    assert "input.cv-kind" in script
    assert 'getAttribute("data-kind")' in script


def test_behaviour_script_contains_no_network_reference() -> None:
    """Neither the script nor the document points at any external resource."""
    document = to_html(_sample_graph())
    script = _behaviour_script(document).lower()

    assert "http://" not in script
    assert "https://" not in script
    assert "fetch(" not in script
    assert "xmlhttprequest" not in script
    assert "http://" not in document.lower()
    assert "https://" not in document.lower()


def test_script_styles_are_declared_inline() -> None:
    """The classes the script toggles are styled by the inline stylesheet."""
    document = to_html(_sample_graph())
    style = document[document.index("<style>") : document.index("</style>")]

    for selector in (".node.cv-hit", ".node.cv-dim", ".graph.cv-panning", ".toolbar"):
        assert selector in style


# --------------------------------------------------------------------------- #
# Layout, ordering and determinism
# --------------------------------------------------------------------------- #


def test_nodes_are_grouped_into_three_kind_columns() -> None:
    """Nodes appear column by column in (column, kind rank, id) order."""
    document = to_html(
        _graph(
            [
                {"id": "z", "label": "z", "kind": "function"},
                {"id": "y", "label": "y", "kind": "entry_point"},
                {"id": "m", "label": "m", "kind": "call_site"},
                {"id": "x", "label": "x", "kind": "import"},
                {"id": "w", "label": "w", "kind": "external"},
                {"id": "v", "label": "v"},
            ],
            [],
        )
    )

    expected = ["y", "z", "m", "x", "w", "v"]
    positions = [document.index(f"<title>{node_id}</title>") for node_id in expected]
    assert positions == sorted(positions)

    assert document.count('class="node col-0"') == 2
    assert document.count('class="node col-1"') == 1
    assert document.count('class="node col-2"') == 3


def test_column_titles_are_rendered() -> None:
    """Each SVG column carries its heading."""
    document = to_html(_sample_graph())

    assert "function / entry_point" in document
    assert "call_site" in document
    assert "import / external / other" in document


def test_node_boxes_show_label_and_kind() -> None:
    """A node box holds its escaped label and a small kind caption."""
    document = to_html(_sample_graph())

    assert 'class="node-label"' in document
    assert 'class="node-kind"' in document
    assert ">main<" in document
    assert ">entry_point<" in document
    assert 'rx="6"' in document


def test_long_labels_are_truncated_for_display_only() -> None:
    """Very long labels are shortened in the SVG but kept whole in the payload."""
    label = "a" * 60
    document = to_html(_graph([{"id": "n", "label": label}], []))

    assert "\u2026" in document
    assert _payload(document)["nodes"][0]["label"] == label


def test_edges_get_arrow_markers() -> None:
    """Every edge is a line that ends with the shared arrow marker."""
    document = to_html(_sample_graph())

    assert '<marker id="arrow"' in document
    assert 'marker-end="url(#arrow)"' in document
    assert document.count('<line class="edge"') == 2


def test_edge_table_lists_every_edge() -> None:
    """The collapsible table repeats the edges with their defaulted labels."""
    document = to_html(_sample_graph())

    assert "<details" in document and "</details>" in document
    assert "<summary>Edges (2)</summary>" in document
    assert "<td>a</td><td>b</td><td>call</td>" in document
    assert "<td>b</td><td>c</td><td>call</td>" in document


def test_output_is_deterministic_and_order_independent() -> None:
    """Repeated calls and reordered input produce byte-identical documents."""
    graph = _sample_graph()
    reordered = _graph(list(reversed(graph["nodes"])), list(reversed(graph["edges"])))

    assert to_html(graph) == to_html(graph)
    assert to_html(graph) == to_html(reordered)
    assert to_html(graph) == to_html(_sample_graph())


def test_two_renders_are_byte_identical_and_valid_utf8() -> None:
    """Two calls on the same graph produce identical, decodable bytes."""
    first = to_html(_sample_graph())
    second = to_html(_sample_graph())

    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")
    assert first.encode("utf-8").decode("utf-8") == first
    assert first.endswith("</html>\n")
    assert first.count(_SCRIPT_OPEN) == 1


def test_payload_is_valid_json_with_the_normalized_graph() -> None:
    """The embedded payload round-trips to the normalized graph."""
    data = _payload(to_html(_sample_graph()))

    assert data["title"] == "CODEVANTA graph"
    assert [node["id"] for node in data["nodes"]] == ["a", "b", "c"]
    assert data["edges"] == [
        {"source": "a", "target": "b", "label": "call"},
        {"source": "b", "target": "c", "label": "call"},
    ]


def test_payload_never_closes_its_script_element() -> None:
    """Embedded data escapes ``</`` so it cannot end the script early."""
    document = to_html(_graph([{"id": "a", "label": "x </script> y"}], []))

    assert "<\\/script>" in document
    # One closing tag for the payload, one for the inline behaviour script.
    assert document.count("</script>") == 2
    start = document.index(_JSON_OPEN) + len(_JSON_OPEN)
    body = document[start : document.index("</script>", start)]
    assert "</" not in body
    assert _payload(document)["nodes"][0]["label"] == "x </script> y"


# --------------------------------------------------------------------------- #
# Validation and module surface
# --------------------------------------------------------------------------- #


def test_max_nodes_overflow_raises() -> None:
    """Graphs larger than the budget are rejected, not truncated."""
    with pytest.raises(GraphExportError, match="max_nodes is 2"):
        to_html(_sample_graph(), max_nodes=2)

    with pytest.raises(GraphExportError, match="max_edges is 1"):
        to_html(_sample_graph(), max_edges=1)

    with pytest.raises(GraphExportError, match=">= 1"):
        to_html(_sample_graph(), max_nodes=0)


@pytest.mark.parametrize("graph", [None, [], "graph", 42])
def test_non_dict_graph_raises(graph) -> None:
    """The viewer shares the exporters' validation messages."""
    with pytest.raises(GraphExportError, match="graph must be a dict"):
        to_html(graph)


def test_invalid_nodes_and_edges_raise() -> None:
    """Unknown endpoints and duplicate ids are rejected before rendering."""
    with pytest.raises(GraphExportError, match="not a known node id"):
        to_html(_graph([{"id": "a", "label": "a"}], [{"source": "a", "target": "ghost"}]))

    with pytest.raises(GraphExportError, match="duplicate node id"):
        to_html(_graph([{"id": "a", "label": "a"}, {"id": "a", "label": "b"}], []))

    with pytest.raises(GraphExportError):
        to_html(_graph([{"id": "a"}], []))


def test_graph_export_error_is_a_value_error() -> None:
    """``GraphExportError`` stays catchable as ``ValueError``."""
    with pytest.raises(ValueError, match="graph must be a dict"):
        to_html(None)


def test_viewer_only_exports_to_html() -> None:
    """The public surface stays a single renderer."""
    assert html_view.__all__ == ["to_html"]


def test_viewer_imports_only_the_standard_library() -> None:
    """The module depends on the stdlib plus the sibling graph exporter."""
    source = Path(html_view.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert imported <= sys.stdlib_module_names | {"codevanta"}

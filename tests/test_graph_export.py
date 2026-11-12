"""Tests for the standalone DOT/GraphML graph exporter.

The tests are self-contained: they build plain-dict graphs inline and parse the
GraphML output with :mod:`xml.etree.ElementTree`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

from codevanta.analysis import graph_export
from codevanta.analysis.graph_export import (
    DEFAULT_EDGE_LABEL,
    DEFAULT_TITLE,
    GraphExportError,
    to_dot,
    to_graphml,
)

EXPORTERS = (to_dot, to_graphml)


def _graph(nodes: list[dict], edges: list[dict]) -> dict:
    """Build a graph mapping from node/edge lists."""
    return {"nodes": nodes, "edges": edges}


def _sample_graph() -> dict:
    """Return a small three-node graph with one labeled and one default edge."""
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


def _local_name(tag: str) -> str:
    """Strip the namespace from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1]


def _elements(root: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    """Return every descendant of ``root`` whose local tag name is ``name``."""
    return [element for element in root.iter() if _local_name(element.tag) == name]


def _key_names(root: ElementTree.Element) -> dict[str, str]:
    """Map GraphML key ids to their declared ``attr.name``."""
    return {key.get("id"): key.get("attr.name") for key in _elements(root, "key")}


def _data(element: ElementTree.Element, keys: dict[str, str]) -> dict[str, str | None]:
    """Collect the ``data`` children of one GraphML element by attribute name."""
    values: dict[str, str | None] = {}
    for child in element:
        if _local_name(child.tag) == "data":
            values[keys.get(child.get("key"))] = child.text
    return values


# --------------------------------------------------------------------------- #
# DOT
# --------------------------------------------------------------------------- #


def test_dot_starts_with_digraph_and_contains_ids() -> None:
    """DOT output is a digraph that mentions every node id and both endpoints."""
    text = to_dot(_sample_graph())

    assert text.startswith("digraph")
    assert text.rstrip().endswith("}")
    assert '"a"' in text
    assert '"b"' in text
    assert '"c"' in text
    assert '"a" -> "b"' in text
    assert '"b" -> "c"' in text


def test_dot_escapes_quotes_in_ids_and_labels() -> None:
    """An embedded double quote is escaped as ``\\"``."""
    text = to_dot(_graph([{"id": 'a"b', "label": 'say "hi"'}], []))

    assert '"a\\"b"' in text
    assert 'say \\"hi\\"' in text


def test_dot_escapes_backslash_and_newline() -> None:
    """Backslashes and newlines are escaped rather than emitted raw."""
    text = to_dot(_graph([{"id": "c:\\tmp\\x", "label": "line1\nline2"}], []))

    assert "c:\\\\tmp\\\\x" in text
    assert "line1\\nline2" in text
    assert "\nline2" not in text


def test_dot_shape_box_for_function_and_entry_point() -> None:
    """``function``/``entry_point`` nodes are boxes; everything else is an ellipse."""
    text = to_dot(_sample_graph())

    assert '"a" [label="main", shape=box];' in text
    assert '"b" [label="parse", shape=box];' in text
    assert '"c" [label="internal.helper", shape=ellipse];' in text


def test_dot_missing_kind_defaults_to_ellipse() -> None:
    """A node without a ``kind`` key is rendered as an ellipse."""
    text = to_dot(_graph([{"id": "n", "label": "n"}], []))

    assert "shape=ellipse" in text


def test_dot_edge_label_defaults_to_call() -> None:
    """An edge without a label gets the default ``call`` label."""
    text = to_dot(_graph([{"id": "a", "label": "a"}], [{"source": "a", "target": "a"}]))

    assert f'[label="{DEFAULT_EDGE_LABEL}"]' in text


def test_dot_uses_title_in_graph_header() -> None:
    """The title is rendered as the graph name and label."""
    text = to_dot(_graph([], []), title="call graph of sample.exe")

    assert text.startswith('digraph "call graph of sample.exe"')
    assert 'graph [label="call graph of sample.exe"];' in text


def test_dot_is_deterministic_regardless_of_input_order() -> None:
    """Reversing insertion order produces byte-identical output."""
    forward = _sample_graph()
    backward = _graph(list(reversed(forward["nodes"])), list(reversed(forward["edges"])))

    assert to_dot(forward) == to_dot(backward)


def test_dot_orders_nodes_by_id_and_edges_by_endpoints() -> None:
    """Nodes are sorted by id and edges by ``(source, target)``."""
    graph = _graph(
        [
            {"id": "z", "label": "z"},
            {"id": "m", "label": "m"},
            {"id": "a", "label": "a"},
        ],
        [
            {"source": "z", "target": "a", "label": "call"},
            {"source": "a", "target": "z", "label": "call"},
            {"source": "m", "target": "a", "label": "call"},
        ],
    )
    body = [line.strip() for line in to_dot(graph).splitlines() if line.strip().startswith('"')]

    assert body == [
        '"a" [label="a", shape=ellipse];',
        '"m" [label="m", shape=ellipse];',
        '"z" [label="z", shape=ellipse];',
        '"a" -> "z" [label="call"];',
        '"m" -> "a" [label="call"];',
        '"z" -> "a" [label="call"];',
    ]


def test_dot_empty_graph_is_still_valid_structure() -> None:
    """An empty graph renders a well-formed, empty digraph."""
    text = to_dot(_graph([], []))

    assert text.count("{") == text.count("}") == 1
    assert "->" not in text


# --------------------------------------------------------------------------- #
# GraphML
# --------------------------------------------------------------------------- #


def test_graphml_parses_with_matching_counts_and_labels() -> None:
    """GraphML round-trips node/edge counts and labels through ElementTree."""
    graph = _sample_graph()
    root = ElementTree.fromstring(to_graphml(graph))
    keys = _key_names(root)

    assert to_graphml(graph).startswith("<?xml")
    assert _local_name(root.tag) == "graphml"
    assert {key.get("for") for key in _elements(root, "key")} == {"node", "edge"}
    assert _elements(root, "node") and _elements(root, "edge")
    assert len(_elements(root, "node")) == len(graph["nodes"])
    assert len(_elements(root, "edge")) == len(graph["edges"])

    labels = {node.get("id"): _data(node, keys)["label"] for node in _elements(root, "node")}
    assert labels == {"a": "main", "b": "parse", "c": "internal.helper"}

    kinds = {node.get("id"): _data(node, keys).get("kind") for node in _elements(root, "node")}
    assert kinds == {"a": "entry_point", "b": "function", "c": "external"}

    edge_labels = {
        (edge.get("source"), edge.get("target")): _data(edge, keys)["label"]
        for edge in _elements(root, "edge")
    }
    assert edge_labels == {("a", "b"): "call", ("b", "c"): DEFAULT_EDGE_LABEL}


def test_graphml_declares_directed_graph_and_desc_title() -> None:
    """The graph element is directed and carries the title in ``desc``."""
    root = ElementTree.fromstring(to_graphml(_sample_graph(), title="xrefs <sample> & co"))

    graphs = _elements(root, "graph")
    assert len(graphs) == 1
    assert graphs[0].get("edgedefault") == "directed"
    assert _elements(root, "desc")[0].text == "xrefs <sample> & co"


def test_graphml_default_title_is_used() -> None:
    """A blank title falls back to the module default in both formats."""
    root = ElementTree.fromstring(to_graphml(_graph([], []), title="   "))

    assert _elements(root, "desc")[0].text == DEFAULT_TITLE
    assert to_dot(_graph([], []), title="").startswith(f'digraph "{DEFAULT_TITLE}"')


def test_graphml_escapes_xml_special_characters() -> None:
    """Labels containing XML metacharacters survive a parse round-trip."""
    label = 'a<b>&"c"\'\nsecond'
    root = ElementTree.fromstring(to_graphml(_graph([{"id": "node <1>", "label": label}], [])))

    node = _elements(root, "node")[0]
    assert node.get("id") == "node <1>"
    assert _data(node, _key_names(root))["label"] == label


def test_graphml_is_deterministic_regardless_of_input_order() -> None:
    """Reversing insertion order produces byte-identical GraphML."""
    forward = _sample_graph()
    backward = _graph(list(reversed(forward["nodes"])), list(reversed(forward["edges"])))

    assert to_graphml(forward) == to_graphml(backward)


def test_graphml_edge_label_defaults_to_call() -> None:
    """An unlabeled edge is exported with the default ``call`` label."""
    root = ElementTree.fromstring(
        to_graphml(_graph([{"id": "a", "label": "a"}], [{"source": "a", "target": "a"}]))
    )

    edge = _elements(root, "edge")[0]
    assert _data(edge, _key_names(root))["label"] == DEFAULT_EDGE_LABEL


def test_graphml_omits_kind_data_when_kind_is_absent() -> None:
    """Nodes without a ``kind`` do not emit an empty kind element."""
    root = ElementTree.fromstring(to_graphml(_graph([{"id": "a", "label": "a"}], [])))

    assert "kind" not in _data(_elements(root, "node")[0], _key_names(root))


def test_graphml_empty_graph_round_trips() -> None:
    """An empty graph yields a valid document with no node/edge elements."""
    root = ElementTree.fromstring(to_graphml(_graph([], [])))

    assert _elements(root, "node") == []
    assert _elements(root, "edge") == []


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("export", EXPORTERS)
def test_duplicate_node_ids_raise(export) -> None:
    """Duplicate node ids are rejected before anything is rendered."""
    graph = _graph([{"id": "dup", "label": "one"}, {"id": "dup", "label": "two"}], [])

    with pytest.raises(GraphExportError, match="duplicate node id"):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
def test_unknown_edge_target_raises(export) -> None:
    """An edge pointing at an unknown node id is rejected."""
    graph = _graph([{"id": "a", "label": "a"}], [{"source": "a", "target": "ghost"}])

    with pytest.raises(GraphExportError, match="ghost"):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
def test_unknown_edge_source_raises(export) -> None:
    """An edge starting at an unknown node id is rejected."""
    graph = _graph([{"id": "a", "label": "a"}], [{"source": "ghost", "target": "a"}])

    with pytest.raises(GraphExportError, match="ghost"):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
def test_max_nodes_limit_raises(export) -> None:
    """Two nodes exceed ``max_nodes=1``."""
    graph = _graph([{"id": "a", "label": "a"}, {"id": "b", "label": "b"}], [])

    with pytest.raises(GraphExportError, match="max_nodes"):
        export(graph, max_nodes=1)


@pytest.mark.parametrize("export", EXPORTERS)
def test_max_edges_limit_raises(export) -> None:
    """Two edges exceed ``max_edges=1``."""
    graph = _graph(
        [{"id": "a", "label": "a"}, {"id": "b", "label": "b"}],
        [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}],
    )

    with pytest.raises(GraphExportError, match="max_edges"):
        export(graph, max_edges=1)


@pytest.mark.parametrize("export", EXPORTERS)
def test_limits_are_inclusive(export) -> None:
    """A graph exactly at both limits is accepted."""
    assert export(_sample_graph(), max_nodes=3, max_edges=2)


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize("bad_limit", [0, -1])
def test_non_positive_limits_raise(export, bad_limit: int) -> None:
    """Limits must be at least one."""
    with pytest.raises(GraphExportError, match=">= 1"):
        export(_graph([], []), max_nodes=bad_limit)
    with pytest.raises(GraphExportError, match=">= 1"):
        export(_graph([], []), max_edges=bad_limit)


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize("bad_limit", ["10", 2.5, None, True])
def test_non_integer_limits_raise(export, bad_limit) -> None:
    """Non-integer (and bool) limits are rejected."""
    with pytest.raises(GraphExportError, match="max_nodes"):
        export(_graph([], []), max_nodes=bad_limit)


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize("graph", [None, [], "graph", 42, ("nodes", "edges")])
def test_non_dict_graph_raises(export, graph) -> None:
    """A graph that is not a dict is rejected."""
    with pytest.raises(GraphExportError, match="graph must be a dict"):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize(
    "graph",
    [
        {"edges": []},
        {"nodes": []},
        {"nodes": "a", "edges": []},
        {"nodes": [], "edges": {"source": "a"}},
    ],
)
def test_malformed_graph_containers_raise(export, graph) -> None:
    """Missing or non-list ``nodes``/``edges`` are rejected."""
    with pytest.raises(GraphExportError):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize(
    "node",
    [
        {"label": "no id"},
        {"id": "a"},
        {"id": "  ", "label": "blank"},
        {"id": "", "label": "empty"},
        {"id": 5, "label": "int id"},
        {"id": "a", "label": 7},
        {"id": "a", "label": "a", "kind": 3},
        "not a dict",
    ],
)
def test_invalid_nodes_raise(export, node) -> None:
    """Nodes must be dicts with a non-blank string id and a string label."""
    with pytest.raises(GraphExportError):
        export(_graph([node], []))


@pytest.mark.parametrize("export", EXPORTERS)
@pytest.mark.parametrize(
    "edge",
    [
        {"source": "a"},
        {"target": "a"},
        {"source": "", "target": "a"},
        {"source": "a", "target": "b", "label": 1},
        ["a", "b"],
    ],
)
def test_invalid_edges_raise(export, edge) -> None:
    """Edges must be dicts with string ``source``/``target`` and optional label."""
    graph = _graph([{"id": "a", "label": "a"}, {"id": "b", "label": "b"}], [edge])

    with pytest.raises(GraphExportError):
        export(graph)


@pytest.mark.parametrize("export", EXPORTERS)
def test_graph_export_error_is_a_value_error(export) -> None:
    """``GraphExportError`` stays catchable as ``ValueError``."""
    with pytest.raises(ValueError, match="graph must be a dict"):
        export(None)


def test_exporter_module_is_standalone() -> None:
    """The module imports nothing but the standard library."""
    source = Path(graph_export.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "codevanta" not in imported
    assert imported <= sys.stdlib_module_names

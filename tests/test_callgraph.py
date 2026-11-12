"""Call-graph construction tests over tiny synthetic ELF64 samples.

Every sample is assembled byte-by-byte with :mod:`struct` inside this module, so
the tests stay self-contained: no shared fixtures, no real-world binaries, and no
symbol tables (function candidates are injected directly).
"""

from __future__ import annotations

import inspect
import struct
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codevanta.analysis.callgraph import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FUNCTIONS,
    MAX_LIMIT,
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    build_call_graph,
)
from codevanta.core.functions import FunctionCandidate
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

TEXT_VA = 0x401000
A_VA = 0x401000
B_VA = 0x401010
FAR_VA = 0x500005
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

#: ``a``: call 0x401010 ; ret ; nop padding ; ``b``: call 0x401010 ; ret.
PAIR_CODE = bytes.fromhex("e80b000000c3") + b"\x90" * 10 + bytes.fromhex("e8fbffffffc3")

#: ``a``: call 0x500005 (no candidate there) ; ret.
FAR_CALL_CODE = bytes.fromhex("e800f00f00c3")

#: ``jmp 0x401002`` ; ``je 0x401004`` ; ``call 0x401000`` ; ``ret``.
MIXED_CODE = bytes.fromhex("eb007400e8f7ffffffc3")


def _write_elf64(
    path: Path,
    code: bytes,
    *,
    text_va: int = TEXT_VA,
    entry: int | None = None,
) -> Path:
    """Write an ELF64 file with a single executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x100
    shstrtab_offset = text_offset + len(code)
    section_headers_offset = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,                            # e_type = ET_EXEC
        62,                           # e_machine = EM_X86_64
        1,                            # e_version
        text_va if entry is None else entry,
        0,                            # e_phoff
        section_headers_offset,       # e_shoff
        0,                            # e_flags
        64,                           # e_ehsize
        56,                           # e_phentsize
        0,                            # e_phnum
        64,                           # e_shentsize
        3,                            # e_shnum (null, .text, .shstrtab)
        2,                            # e_shstrndx
    )
    blob = bytearray(section_headers_offset)
    blob[0:64] = header
    blob[text_offset:text_offset + len(code)] = code
    blob[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    blob += bytes(64)  # SHT_NULL section header
    blob += struct.pack(
        "<IIQQQQIIQQ",
        1,                                # sh_name -> ".text"
        1,                                # sh_type = SHT_PROGBITS
        SHF_ALLOC | SHF_EXECINSTR,        # sh_flags
        text_va,                          # sh_addr
        text_offset,                      # sh_offset
        len(code),                        # sh_size
        0,                                # sh_link
        0,                                # sh_info
        16,                               # sh_addralign
        0,                                # sh_entsize
    )
    blob += struct.pack(
        "<IIQQQQIIQQ",
        7,                                # sh_name -> ".shstrtab"
        3,                                # sh_type = SHT_STRTAB
        0,                                # sh_flags
        0,                                # sh_addr
        shstrtab_offset,                  # sh_offset
        len(shstrtab),                    # sh_size
        0,                                # sh_link
        0,                                # sh_info
        1,                                # sh_addralign
        0,                                # sh_entsize
    )
    path.write_bytes(bytes(blob))
    return path


def _load(path: Path) -> BinaryInfo:
    """Load synthetic metadata for ``path`` through the real loader."""
    return BinaryLoader().load(path)


def _function(
    address: int,
    name: str | None = None,
    confidence: Confidence = Confidence.HIGH,
) -> FunctionCandidate:
    """Build a hand-made function candidate for graph tests."""
    return FunctionCandidate(
        address=address,
        name=name,
        size=None,
        source="test.hand_built",
        confidence=confidence,
        evidence=Evidence(
            source="test.hand_built",
            method="unit_test",
            confidence=confidence,
            address=address,
        ),
    )


def _edges(graph: CallGraph) -> list[tuple[int | None, int | None, int]]:
    """Return edges as ``(source, target, from_address)`` tuples."""
    return [(edge.source, edge.target, edge.from_address) for edge in graph.edges]


def test_both_direct_calls_produce_edges(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "pair.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a"), _function(B_VA, "b")])

    assert _edges(graph) == [
        (A_VA, B_VA, A_VA),      # call 0x401010 from the entry function
        (B_VA, B_VA, B_VA),      # call 0x401010 from b (a self call)
    ]
    assert graph.truncated is False
    assert graph.warnings == ()


def test_nodes_cover_every_candidate_once(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "pair.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a"), _function(B_VA, "b")])

    assert [(node.address, node.label) for node in graph.nodes] == [(A_VA, "a"), (B_VA, "b")]
    assert all(node.kind == "function" or node.kind == "entry_point" for node in graph.nodes)


def test_entry_point_candidate_gets_entry_point_kind(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "pair.bin", PAIR_CODE)
    info = _load(path)
    assert info.entry_point == A_VA

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a"), _function(B_VA, "b")])

    by_address = {node.address: node for node in graph.nodes}
    assert by_address[A_VA].kind == "entry_point"
    assert by_address[B_VA].kind == "function"
    assert by_address[A_VA].confidence == Confidence.HIGH.value
    assert by_address[B_VA].confidence == Confidence.HIGH.value


def test_unresolved_target_becomes_external_node(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "far.bin", FAR_CALL_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a")])

    assert _edges(graph) == [(A_VA, FAR_VA, A_VA)]
    external = graph.nodes[-1]
    assert external.address == FAR_VA
    assert external.kind == "external"
    assert external.confidence == "unknown"


def test_external_node_is_shared_by_repeated_targets(tmp_path: Path) -> None:
    # call 0x401010 twice (a at .text+0, b at .text+0x10) with b unknown to us.
    path = _write_elf64(tmp_path / "unknown.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a")])

    externals = [node for node in graph.nodes if node.kind == "external"]
    assert [node.address for node in externals] == [B_VA]


def test_jump_and_branch_references_are_ignored(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "mixed.bin", MIXED_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a")])

    # The jmp/je cross references (0x401002, 0x401004) never become edges.
    assert _edges(graph) == [(A_VA, A_VA, 0x401004)]
    assert all(edge.label == "call" for edge in graph.edges)


def test_max_edges_marks_graph_truncated(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "cut.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(
        path,
        info,
        functions=[_function(A_VA, "a"), _function(B_VA, "b")],
        max_edges=1,
    )

    assert graph.truncated is True
    assert _edges(graph) == [(A_VA, B_VA, A_VA)]
    assert any("edge limit reached" in warning for warning in graph.warnings)


def test_max_functions_marks_graph_truncated(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "few.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(
        path,
        info,
        functions=[_function(A_VA, "a"), _function(B_VA, "b")],
        max_functions=1,
    )

    assert graph.truncated is True
    assert any("function limit reached" in warning for warning in graph.warnings)
    # Only the entry function survives; the dropped callee degrades to external.
    assert [(node.address, node.kind) for node in graph.nodes] == [
        (A_VA, "entry_point"),
        (B_VA, "external"),
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_functions": 0},
        {"max_functions": -1},
        {"max_functions": MAX_LIMIT + 1},
        {"max_edges": 0},
        {"max_edges": -5},
        {"max_edges": MAX_LIMIT + 1},
    ],
)
def test_out_of_range_limits_are_rejected(tmp_path: Path, kwargs: dict[str, int]) -> None:
    path = _write_elf64(tmp_path / "limits.bin", PAIR_CODE)
    info = _load(path)

    with pytest.raises(AnalysisError):
        build_call_graph(path, info, functions=[_function(A_VA, "a")], **kwargs)


def test_limits_at_the_boundary_are_accepted(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "bound.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(
        path,
        info,
        functions=[_function(A_VA, "a")],
        max_functions=MAX_LIMIT,
        max_edges=MAX_LIMIT,
    )

    assert isinstance(graph, CallGraph)
    assert graph.truncated is False


def test_candidates_are_discovered_when_not_supplied(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "discover.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(path, info)  # no injected candidates

    # Discovery only reports the entry point for this symbol-less ELF.
    assert [(node.address, node.kind) for node in graph.nodes] == [
        (A_VA, "entry_point"),
        (B_VA, "external"),
    ]
    assert graph.edges[0].source == A_VA


def test_unattributed_caller_uses_call_address_and_warns_once(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "late.bin", bytes.fromhex("e80b000000c3"))
    info = _load(path)

    # The only candidate starts *after* the call site, so no caller is known.
    graph = build_call_graph(path, info, functions=[_function(0x401020, "later")])

    assert _edges(graph) == [(A_VA, B_VA, A_VA)]
    caller_warnings = [w for w in graph.warnings if "caller attribution failed" in w]
    assert len(caller_warnings) == 1
    assert "1 call site(s)" in caller_warnings[0]


def test_duplicate_candidates_collapse_to_one_node(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "dupe.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(
        path,
        info,
        functions=[
            _function(A_VA, "weak", Confidence.LOW),
            _function(A_VA, "strong", Confidence.HIGH),
        ],
    )

    node = next(node for node in graph.nodes if node.address == A_VA)
    assert node.label == "strong"
    assert node.confidence == Confidence.HIGH.value
    assert len([n for n in graph.nodes if n.address == A_VA]) == 1


def test_graph_evidence_states_limits(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "evidence.bin", PAIR_CODE)
    info = _load(path)

    graph = build_call_graph(path, info, functions=[_function(A_VA, "a"), _function(B_VA, "b")])

    assert graph.evidence.source == "callgraph.direct_calls"
    assert graph.evidence.method == "xref_aggregation"
    assert graph.evidence.confidence is Confidence.MEDIUM
    assert "heuristic" in (graph.evidence.detail or "")
    assert "direct calls" in (graph.evidence.detail or "")


def test_to_dict_serializes_hex_addresses(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "dict.bin", FAR_CALL_CODE)
    info = _load(path)

    data = build_call_graph(path, info, functions=[_function(A_VA, "a")]).to_dict()

    assert data["node_count"] == 2
    assert data["edge_count"] == 1
    assert data["nodes"][0] == {
        "address": "0x401000",
        "label": "a",
        "kind": "entry_point",
        "confidence": "high",
    }
    assert data["nodes"][1]["address"] == "0x500005"
    assert data["nodes"][1]["kind"] == "external"
    assert data["edges"][0] == {
        "source": "0x401000",
        "target": "0x500005",
        "from_address": "0x401000",
        "label": "call",
    }
    assert data["truncated"] is False
    assert data["evidence"]["source"] == "callgraph.direct_calls"
    assert data["evidence"]["confidence"] == "medium"


def test_graph_model_ids_reference_existing_nodes(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "model.bin", PAIR_CODE)
    info = _load(path)

    model = build_call_graph(
        path, info, functions=[_function(A_VA, "a"), _function(B_VA, "b")]
    ).to_graph_model()

    ids = {node["id"] for node in model["nodes"]}
    assert ids == {"0x401000", "0x401010"}
    assert all(isinstance(node_id, str) for node_id in ids)
    for edge in model["edges"]:
        assert isinstance(edge["source"], str)
        assert isinstance(edge["target"], str)
        assert edge["source"] in ids
        assert edge["target"] in ids
    assert {"source": "0x401000", "target": "0x401010", "from_address": "0x401000"} == {
        key: model["edges"][0][key] for key in ("source", "target", "from_address")
    }
    assert model["truncated"] is False


def test_graph_model_marks_external_ids(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "model2.bin", FAR_CALL_CODE)
    info = _load(path)

    model = build_call_graph(path, info, functions=[_function(A_VA, "a")]).to_graph_model()

    assert [node["id"] for node in model["nodes"]] == ["0x401000", "external:0x500005"]
    assert model["edges"][0]["target"] == "external:0x500005"


def test_graph_model_adds_nodes_for_unattributed_call_sites(tmp_path: Path) -> None:
    path = _write_elf64(tmp_path / "model3.bin", PAIR_CODE)
    info = _load(path)

    # Only the callee is a candidate, so the call at 0x401000 has no candidate at
    # or below it and keeps the call address as its edge source.
    model = build_call_graph(path, info, functions=[_function(B_VA, "b")]).to_graph_model()

    ids = {node["id"] for node in model["nodes"]}
    assert "0x401000" in ids
    call_site = next(node for node in model["nodes"] if node["id"] == "0x401000")
    assert call_site["kind"] == "call_site"
    for edge in model["edges"]:
        assert edge["source"] in ids
        assert edge["target"] in ids


def test_dataclasses_are_frozen_and_defaults_hold() -> None:
    node = CallGraphNode(address=None, label="x", kind="external", confidence="unknown")
    edge = CallGraphEdge(source=None, target=None, from_address=0x10)
    graph = CallGraph(
        nodes=[node],
        edges=[edge],
        truncated=False,
        evidence=Evidence(
            source="callgraph.direct_calls",
            method="xref_aggregation",
            confidence=Confidence.MEDIUM,
        ),
    )

    assert edge.label == "call"
    assert graph.warnings == ()
    assert node.to_dict()["address"] is None
    assert edge.to_dict()["source"] is None
    # Unresolved addresses still produce string ids instead of crashing.
    assert graph.to_graph_model()["nodes"][0]["id"] == "unresolved"
    with pytest.raises(FrozenInstanceError):
        graph.truncated = True  # type: ignore[misc]


def test_signature_uses_documented_defaults() -> None:
    params = inspect.signature(build_call_graph).parameters

    assert params["max_functions"].default == DEFAULT_MAX_FUNCTIONS == 2_000
    assert params["max_edges"].default == DEFAULT_MAX_EDGES == 20_000
    assert params["functions"].default is None

"""Search-lane tests over synthetic in-memory data and tiny synthetic ELF64.

No real-world binaries: every sample is built byte-by-byte in this module,
so the lane's guarantees (typed results, bounds, honesty) are tested offline
against data whose expected answer is known exactly. The MCP-layer tests at
the bottom exercise the file-reading wrappers through
``codevanta.mcp_server.tools``.
"""

from __future__ import annotations

import json
import struct
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis import search
from codevanta.analysis.callgraph import CallGraph, CallGraphEdge, CallGraphNode
from codevanta.analysis.search import (
    CallPath,
    GraphSubset,
    NavContext,
    Proc,
    SearchHits,
    build_call_path,
    get_call_graph_subset,
    navigate,
    procedures,
    search_bytes,
    search_procedures,
    search_strings,
)
from codevanta.core.loader import BinaryInfo, SectionInfo, SymbolInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence
from codevanta.mcp_server import ext_search
from codevanta.mcp_server import tools as mcp_tools

# ---- synthetic data --------------------------------------------------------

#: Offset 0x10: "8B 44 24 08" and offset 0x30: "8B 44 99 08".
PATTERN_DATA = bytes(0x10) + bytes.fromhex("8b442408") + bytes(0x1C) + bytes.fromhex("8b449908")

#: ASCII at 0x04, UTF-16LE "Wide" at 0x20, plus a long ASCII run.
STRINGS_DATA = (
    bytes(0x04)
    + b"Hello.World"
    + bytes(0x08)
    + "Wide".encode("utf-16-le")
    + bytes(0x04)
    + b"X" * 300
    + bytes(0x04)
)

A, B, C, D = 0x1000, 0x1010, 0x1020, 0x1030


def _edges() -> list[CallGraphEdge]:
    """Chain a -> b -> c -> d plus an unresolved-source edge and a fork."""
    return [
        CallGraphEdge(source=A, target=B, from_address=A + 4),
        CallGraphEdge(source=B, target=C, from_address=B + 4),
        CallGraphEdge(source=C, target=D, from_address=C + 4),
        CallGraphEdge(source=B, target=D, from_address=B + 8),
        CallGraphEdge(source=None, target=A, from_address=0x900),
    ]


def _chain_graph() -> CallGraph:
    """The chain above with proper node labels."""
    nodes = [
        CallGraphNode(address=addr, label=f"fn_{addr:x}", kind="function", confidence="high")
        for addr in (A, B, C, D)
    ]
    return CallGraph(
        nodes=nodes,
        edges=_edges(),
        truncated=False,
        evidence=Evidence(source="test", method="test"),
    )


def _info(path: Path = Path("synthetic.bin")) -> BinaryInfo:
    """A loaded-binary stand-in with one section and two function symbols."""
    return BinaryInfo(
        path=path,
        format="ELF",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=0x401000,
        image_base=0x400000,
        sha256="0" * 64,
        file_size=0x200,
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x401000,
                size=0x100,
                offset=0x40,
                raw_size=0x100,
                is_executable=True,
            )
        ],
        symbols=[
            SymbolInfo(name="CreateFileW", address=0x401010, size=0x20, is_function=True),
            SymbolInfo(name="create_helper", address=0x401030, size=None, is_function=True),
        ],
    )


def _procs() -> list[Proc]:
    """Explicit inventory: sized, size-less, and out of order on purpose."""
    return [
        Proc(address=0x401030, name="create_helper", size=None),
        Proc(address=0x401000, name="sub_401000", size=0x10),
        Proc(address=0x401010, name="CreateFileW", size=0x20),
    ]


def _write_elf64(path: Path, code: bytes, *, text_address: int = 0x401000) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = (text_offset + len(code) + 7) & ~7
    shoff = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, text_address, 0, shoff, 0, 64, 56, 0, 64, 3, 2
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, text_address, text_offset, len(code), 0, 0, 16, 0
    )
    shstr_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstr_section
    path.write_bytes(bytes(blob))
    return path


# ---- search_bytes ----------------------------------------------------------


def test_search_bytes_finds_literal() -> None:
    result = search_bytes(PATTERN_DATA, "8B 44 24 08")
    assert result.total == 1
    assert result.truncated is False
    hit = result.hits[0]
    assert hit.offset == 0x10
    assert "8b442408" in hit.context
    assert len(hit.context) <= (4 + 2 * search.CONTEXT_RADIUS) * 2
    assert result.evidence.source == "search.bytes"
    assert result.evidence.confidence is Confidence.CERTAIN


def test_search_bytes_wildcards_match_both_sites() -> None:
    result = search_bytes(PATTERN_DATA, "8B 44 ?? 08")
    assert result.total == 2
    assert [hit.offset for hit in result.hits] == [0x10, 0x30]


def test_search_bytes_mask_ignores_byte() -> None:
    result = search_bytes(PATTERN_DATA, "8B 44 24 08", mask="xx?x")
    assert result.total == 2  # the third byte is ignored, like a wildcard


def test_search_bytes_window_bounds_scan() -> None:
    assert search_bytes(PATTERN_DATA, "8B 44 ?? 08", start=0x20).total == 1
    assert search_bytes(PATTERN_DATA, "8B 44 ?? 08", start=0, end=0x20).total == 1
    assert search_bytes(PATTERN_DATA, "8B 44 ?? 08", start=0x20, end=0x30).total == 0


def test_search_bytes_limit_truncates_but_total_counts() -> None:
    data = b"\x90" * 100
    result = search_bytes(data, "90", limit=2)
    assert result.total == 100
    assert len(result.hits) == 2
    assert result.truncated is True


def test_search_bytes_context_clamps_at_window_edges() -> None:
    result = search_bytes(b"\x41\x42\x43", "41 42")
    assert result.hits[0].context == "414243"  # clamped at the start, open to the right


def test_search_bytes_no_match_is_empty_not_error() -> None:
    result = search_bytes(PATTERN_DATA, "DE AD BE EF")
    assert result.total == 0
    assert result.hits == ()


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"pattern": ""}, "pattern"),
        ({"pattern": "8B4"}, "whole hex bytes"),
        ({"pattern": "8B 4X"}, "hex digits"),
        ({"pattern": "?? ??"}, "concrete"),
        ({"pattern": "8B" * 300}, "at most"),
        ({"pattern": "8B 44 24 08", "mask": "xxxxx"}, "per pattern byte"),
        ({"pattern": "8B 44 24 08", "mask": "xxxy"}, "'x' or '?'"),
        ({"pattern": "90", "limit": 0}, "limit"),
        ({"pattern": "90", "limit": search.MAX_HITS_LIMIT + 1}, "limit"),
        ({"pattern": "90", "start": -1}, "start"),
        ({"pattern": "90", "start": 4, "end": 2}, "end"),
    ],
)
def test_search_bytes_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(AnalysisError, match=match):
        search_bytes(PATTERN_DATA, **kwargs)


def test_search_bytes_rejects_non_bytes() -> None:
    with pytest.raises(AnalysisError, match="bytes"):
        search_bytes("not bytes", "90")  # type: ignore[arg-type]


def test_search_bytes_frozen_result() -> None:
    result: SearchHits = search_bytes(PATTERN_DATA, "8B 44 24 08")
    with pytest.raises(FrozenInstanceError):
        result.total = 99  # type: ignore[misc]


# ---- search_strings --------------------------------------------------------


def test_search_strings_finds_ascii_literal() -> None:
    result = search_strings(STRINGS_DATA, "World")
    assert result.total == 1
    match = result.matches[0]
    assert match.offset == 0x04
    assert match.text == "Hello.World"
    assert match.length == 11
    assert result.evidence.source == "search.strings"


def test_search_strings_case_insensitive_literal() -> None:
    assert search_strings(STRINGS_DATA, "world", case_sensitive=False).total == 1
    assert search_strings(STRINGS_DATA, "world").total == 0


def test_search_strings_regex_mode() -> None:
    result = search_strings(STRINGS_DATA, "W.rld", mode="regex", case_sensitive=False)
    assert result.total == 1
    assert result.matches[0].text == "Hello.World"


def test_search_strings_finds_utf16() -> None:
    result = search_strings(STRINGS_DATA, "Wide")
    assert result.total == 1
    assert result.matches[0].offset == 0x17
    assert result.matches[0].length == 4


def test_search_strings_text_capped_length_honest() -> None:
    result = search_strings(STRINGS_DATA, "XXX")
    assert result.total == 1
    match = result.matches[0]
    assert len(match.text) == search.MAX_TEXT_CHARS
    assert match.length == 300


def test_search_strings_limit_truncates_but_total_counts() -> None:
    data = b"alpha\x00beta\x00gamma."
    result = search_strings(data, "a", limit=2)
    assert result.total == 3
    assert len(result.matches) == 2
    assert result.truncated is True


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"query": ""}, "query"),
        ({"query": "   "}, "query"),
        ({"query": "World", "mode": "fuzzy"}, "mode"),
        ({"query": "W(rld", "mode": "regex"}, "regex"),
        ({"query": "World", "limit": 0}, "limit"),
        ({"query": "World", "limit": search.MAX_MATCH_LIMIT + 1}, "limit"),
    ],
)
def test_search_strings_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(AnalysisError, match=match):
        search_strings(STRINGS_DATA, **kwargs)


def test_search_strings_rejects_non_bytes() -> None:
    with pytest.raises(AnalysisError, match="bytes"):
        search_strings(42, "x")  # type: ignore[arg-type]


# ---- procedures ------------------------------------------------------------


def test_procedures_from_info_sorts_and_defaults_names() -> None:
    procs = procedures(_info())
    assert [proc.address for proc in procs] == [0x401000, 0x401010, 0x401030]
    assert procs[0].name == "sub_401000"  # entry point without a symbol name
    assert procs[0].size is None
    assert procs[1].name == "CreateFileW"
    assert procs[1].size == 0x20


def test_search_procs_literal_from_inventory() -> None:
    result = search_procedures(_procs(), "create")
    assert result.total == 1  # matching is case-sensitive: only create_helper
    assert result.matches[0].name == "create_helper"
    assert result.evidence.source == "search.procs"


def test_search_procs_case_sensitive_literal() -> None:
    assert search_procedures(_procs(), "createfile").total == 0
    assert search_procedures(_procs(), "CreateFile").total == 1


def test_search_procs_regex_from_info() -> None:
    result = search_procedures(_info(), "^create", mode="regex")
    assert result.total == 1
    assert result.matches[0].name == "create_helper"


def test_search_procs_limit_truncates() -> None:
    result = search_procedures(_procs(), "sub_|create", mode="regex", limit=1)
    assert result.total == 2
    assert len(result.matches) == 1
    assert result.truncated is True


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"pattern": ""}, "pattern"),
        ({"pattern": "   "}, "pattern"),
        ({"pattern": "x", "mode": "glob"}, "mode"),
        ({"pattern": "x(", "mode": "regex"}, "regex"),
        ({"pattern": "x", "limit": 0}, "limit"),
    ],
)
def test_search_procs_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(AnalysisError, match=match):
        search_procedures(_procs(), **kwargs)


def test_search_procs_rejects_bad_inventory() -> None:
    with pytest.raises(AnalysisError, match="Proc"):
        search_procedures([("0x401000", "name")], "x")  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="sequence"):
        search_procedures("procs", "x")  # type: ignore[arg-type]


# ---- build_call_path -------------------------------------------------------


def test_call_path_finds_shortest_chain_through_graph() -> None:
    result = build_call_path(_chain_graph(), A, D)
    assert result.found is True
    assert result.length == 2  # a -> b -> d beats a -> b -> c -> d
    assert [node.address for node in result.path] == [A, B, D]
    assert result.path[0].name == "fn_1000"
    assert result.evidence.source == "search.callpath"


def test_call_path_works_on_bare_edge_sequence() -> None:
    result = build_call_path(_edges(), A, D)
    assert result.found is True
    assert result.length == 2
    assert result.path[2].name == "sub_1030"  # no node labels on a bare sequence


def test_call_path_start_equals_goal() -> None:
    result = build_call_path(_chain_graph(), C, C)
    assert result.found is True
    assert result.length == 0
    assert len(result.path) == 1
    assert result.path[0].address == C


def test_call_path_unreachable_returns_not_found() -> None:
    lonely = [CallGraphEdge(source=0x2000, target=0x2010, from_address=0x2004)]
    result = build_call_path(lonely, 0x2000, D)
    assert result.found is False
    assert result.path == ()
    assert result.length == 0


def test_call_path_depth_budget_returns_not_found() -> None:
    result = build_call_path(_chain_graph(), A, D, max_depth=1)
    assert result.found is False


def test_call_path_missing_endpoint_returns_not_found() -> None:
    assert build_call_path(_chain_graph(), 0xDEAD, D).found is False
    assert build_call_path(_chain_graph(), A, 0xDEAD).found is False


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"start_addr": -1}, "start_addr"),
        ({"goal_addr": True}, "goal_addr"),
        ({"max_depth": 0}, "max_depth"),
        ({"max_depth": search.MAX_PATH_DEPTH + 1}, "max_depth"),
    ],
)
def test_call_path_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    params: dict[str, Any] = {"start_addr": A, "goal_addr": D, "max_depth": 8}
    params.update(kwargs)
    with pytest.raises(AnalysisError, match=match):
        build_call_path(_chain_graph(), **params)


def test_call_path_rejects_bad_inventory() -> None:
    with pytest.raises(AnalysisError, match="CallGraphEdge"):
        build_call_path(["edge"], A, D)  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="sequence"):
        build_call_path("edges", A, D)  # type: ignore[arg-type]


def test_call_path_frozen_result() -> None:
    result: CallPath = build_call_path(_chain_graph(), A, D)
    with pytest.raises(FrozenInstanceError):
        result.found = False  # type: ignore[misc]


# ---- get_call_graph_subset -------------------------------------------------


def test_subset_callees_carries_depths() -> None:
    subset = get_call_graph_subset(_chain_graph(), A, direction="callees", max_depth=1)
    assert subset.root == A
    assert subset.direction == "callees"
    assert [(node.address, node.depth) for node in subset.nodes] == [(A, 0), (B, 1)]
    assert [(edge.source, edge.target) for edge in subset.edges] == [(A, B)]
    assert subset.truncated is False
    assert subset.evidence.source == "search.graph_subset"


def test_subset_callers_reverses_walk() -> None:
    subset = get_call_graph_subset(_chain_graph(), D, direction="callers", max_depth=2)
    addresses = {node.address for node in subset.nodes}
    assert addresses == {A, B, C, D}


def test_subset_isolated_address_is_empty_not_error() -> None:
    subset = get_call_graph_subset(_chain_graph(), 0xDEAD)
    assert subset.nodes == ()
    assert subset.edges == ()


def test_subset_node_cap_sets_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search, "MAX_SUBSET_NODES", 2)
    subset = get_call_graph_subset(_chain_graph(), A, direction="callees", max_depth=4)
    assert subset.truncated is True
    assert len(subset.nodes) == 2


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"address": -1}, "address"),
        ({"address": False}, "address"),
        ({"direction": "both"}, "direction"),
        ({"max_depth": 0}, "max_depth"),
        ({"max_depth": search.MAX_SUBSET_DEPTH + 1}, "max_depth"),
    ],
)
def test_subset_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    params: dict[str, Any] = {"address": A, "direction": "callers", "max_depth": 3}
    params.update(kwargs)
    with pytest.raises(AnalysisError, match=match):
        get_call_graph_subset(_chain_graph(), **params)


def test_subset_rejects_bad_graph_source() -> None:
    with pytest.raises(AnalysisError, match="CallGraphEdge"):
        get_call_graph_subset([42], A)  # type: ignore[list-item]


def test_subset_frozen_result() -> None:
    subset: GraphSubset = get_call_graph_subset(_chain_graph(), A)
    with pytest.raises(FrozenInstanceError):
        subset.direction = "callees"  # type: ignore[misc]


# ---- navigate --------------------------------------------------------------


def test_navigate_reports_containing_prev_next_and_section() -> None:
    context = navigate(
        PATTERN_DATA,
        0x401015,
        procs=_procs(),
        sections=_info().sections,
        preview=8,
    )
    assert context.containing is not None
    assert context.containing.name == "CreateFileW"  # 0x401010 + 0x20 spans 0x401015
    assert context.previous is not None
    assert context.previous.name == "sub_401000"
    assert context.next is not None
    assert context.next.name == "create_helper"
    assert context.section == ".text"
    assert context.evidence.source == "search.navigate"


def test_navigate_maps_preview_through_section_offset() -> None:
    data = bytes(0x40) + b"\xe8\x0b\x00\x00\x00\xc3"
    sections = [SectionInfo(name=".text", virtual_address=0x401000, size=6, offset=0x40)]
    context = navigate(data, 0x401000, sections=sections, preview=6)
    assert context.preview_offset == 0x40
    assert context.preview == "e80b000000c3"


def test_navigate_preview_bounded_by_section_and_file() -> None:
    data = bytes(0x40) + b"\x90\x90"
    sections = [SectionInfo(name=".text", virtual_address=0x401000, size=2, offset=0x40)]
    context = navigate(data, 0x401001, sections=sections, preview=64)
    assert context.preview == "90"


def test_navigate_flat_buffer_when_no_sections() -> None:
    context = navigate(b"\xde\xad\xbe\xef", 2, preview=2)
    assert context.section is None
    assert context.preview_offset == 2
    assert context.preview == "beef"


def test_navigate_address_outside_data_gives_empty_preview() -> None:
    context = navigate(b"\x00" * 4, 0x1000)
    assert context.preview_offset is None
    assert context.preview == ""


def test_navigate_without_procs_has_no_neighbours() -> None:
    context = navigate(PATTERN_DATA, 0x10)
    assert context.containing is None
    assert context.previous is None
    assert context.next is None


def test_navigate_before_first_proc_points_forward_only() -> None:
    context = navigate(PATTERN_DATA, 0x401000 - 1, procs=_procs())
    assert context.containing is None
    assert context.previous is None
    assert context.next is not None
    assert context.next.address == 0x401000


def test_navigate_address_below_section_is_none_section() -> None:
    context = navigate(PATTERN_DATA, 0x400000, sections=_info().sections)
    assert context.section is None


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"address": -1}, "address"),
        ({"address": True}, "address"),
        ({"preview": 0}, "preview"),
        ({"preview": search.MAX_PREVIEW_BYTES + 1}, "preview"),
    ],
)
def test_navigate_rejects_bad_input(kwargs: dict[str, Any], match: str) -> None:
    params: dict[str, Any] = {"address": 0x10, "preview": 8}
    params.update(kwargs)
    with pytest.raises(AnalysisError, match=match):
        navigate(PATTERN_DATA, **params)


def test_navigate_rejects_bad_items_and_data() -> None:
    with pytest.raises(AnalysisError, match="Proc"):
        navigate(PATTERN_DATA, 0x10, procs=["x"])  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="SectionInfo"):
        navigate(PATTERN_DATA, 0x10, sections=["x"])  # type: ignore[list-item]
    with pytest.raises(AnalysisError, match="bytes"):
        navigate("data", 0x10)  # type: ignore[arg-type]


def test_navigate_frozen_result() -> None:
    context: NavContext = navigate(PATTERN_DATA, 0x10)
    with pytest.raises(FrozenInstanceError):
        context.address = 0  # type: ignore[misc]


# ---- JSON safety -----------------------------------------------------------


def test_all_results_are_json_safe() -> None:
    payloads = [
        search_bytes(PATTERN_DATA, "8B 44 24 08").to_dict(),
        search_strings(STRINGS_DATA, "World").to_dict(),
        search_procedures(_procs(), "create").to_dict(),
        build_call_path(_chain_graph(), A, D).to_dict(),
        get_call_graph_subset(_chain_graph(), A).to_dict(),
        navigate(PATTERN_DATA, 0x10, procs=_procs()).to_dict(),
    ]
    for payload in payloads:
        json.dumps(payload)  # must not raise


# ---- MCP layer -------------------------------------------------------------


@pytest.fixture
def call_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` is ``call 0x401010; ret``."""
    return _write_elf64(tmp_path / "call.bin", bytes.fromhex("e80b000000c3"))


def test_mcp_search_bytes_on_file(tmp_path: Path) -> None:
    sample = tmp_path / "blob.bin"
    sample.write_bytes(PATTERN_DATA)
    payload = mcp_tools.codevanta_search_bytes(str(sample), "8B 44 ?? 08")
    assert payload["total"] == 2
    assert payload["hits"][0]["offset"] == "0x10"
    assert payload["evidence"]["source"] == "search.bytes"


def test_mcp_search_strings_on_file(tmp_path: Path) -> None:
    sample = tmp_path / "blob.bin"
    sample.write_bytes(STRINGS_DATA)
    payload = mcp_tools.codevanta_search_strings(str(sample), "World")
    assert payload["total"] == 1
    assert payload["matches"][0]["text"] == "Hello.World"


def test_mcp_search_procs_on_elf(elf64_path: Path) -> None:
    payload = mcp_tools.codevanta_search_procs(str(elf64_path), "sub_")
    assert payload["total"] == 1
    assert payload["matches"][0]["address"] == "0x401000"


def test_mcp_call_path_on_elf(call_elf_path: Path) -> None:
    payload = mcp_tools.codevanta_call_path(str(call_elf_path), 0x401000, 0x401010)
    assert payload["found"] is True
    assert payload["length"] == 1
    assert payload["path"][0]["address"] == "0x401000"


def test_mcp_navigate_on_elf(call_elf_path: Path) -> None:
    payload = mcp_tools.codevanta_navigate(str(call_elf_path), 0x401000)
    assert payload["section"] == ".text"
    assert payload["preview"] == "e80b000000c3"
    assert payload["containing"]["address"] == "0x401000"


def test_mcp_graph_subset_on_elf(call_elf_path: Path) -> None:
    callees = mcp_tools.codevanta_graph_subset(str(call_elf_path), 0x401000, direction="callees")
    assert callees["node_count"] == 2
    assert callees["edges"][0]["target"] == "0x401010"
    callers = mcp_tools.codevanta_graph_subset(str(call_elf_path), 0x401010, direction="callers")
    assert callers["node_count"] == 2


def test_mcp_layer_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not found"):
        mcp_tools.codevanta_search_bytes(str(tmp_path / "missing.bin"), "90")


def test_mcp_layer_rejects_oversize_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"\x00" * 32)
    monkeypatch.setattr(ext_search, "MAX_DATA_BYTES", 8)
    with pytest.raises(AnalysisError, match="at most"):
        mcp_tools.codevanta_search_bytes(str(sample), "00")


def test_mcp_graph_subset_bad_direction(call_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="direction"):
        mcp_tools.codevanta_graph_subset(str(call_elf_path), 0x401000, direction="both")

"""MCP tool layer tests (plain functions and in-process server)."""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from starlette.requests import Request

from codevanta.analysis.binary_diff import DEFAULT_SEMANTIC_THRESHOLD
from codevanta.analysis.decompilers import available_backends
from codevanta.analysis.type_recovery import MAX_MAX_FIELDS, MAX_MAX_INSTRUCTIONS
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import server as mcp_server
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server
from codevanta.storage.session import SessionError


def test_binary_info_on_elf(elf64_path: Path) -> None:
    info = tools.binary_info(str(elf64_path))
    assert info["format"] == "ELF"
    assert info["architecture"] == "x86_64"
    assert info["entry_point"] == "0x401000"


def test_binary_info_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        tools.binary_info(str(tmp_path / "missing.bin"))


def test_functions_reports_entry_point(elf64_path: Path) -> None:
    payload = tools.functions(str(elf64_path))
    assert payload["count"] == 1
    item = payload["items"][0]
    assert item["source"] == "binary.entry_point"
    assert item["confidence"] == "medium"


def test_strings_and_disasm_on_elf(elf64_text_path: Path) -> None:
    payload = tools.strings(str(elf64_text_path), min_length=3)
    assert "items" in payload
    disassembly = tools.disasm(str(elf64_text_path), count=3)
    assert [item["text"] for item in disassembly["instructions"]] == [
        "push rbp",
        "mov rbp, rsp",
        "ret",
    ]


def test_analyze_has_provenance(elf64_text_path: Path) -> None:
    report = tools.analyze(str(elf64_text_path))
    assert report["provenance"]["tool"] == "codevanta"
    assert report["binary"]["format"] == "ELF"
    assert report["disassembly"]["instruction_count"] == 3


def test_server_lists_fifty_five_tools() -> None:
    listed = asyncio.run(build_server().list_tools())
    names = sorted(tool.name for tool in listed)
    assert len(names) == 55
    assert names == [
    "codevanta_adb",
    "codevanta_analyze",
    "codevanta_apk_decode",
    "codevanta_asar",
    "codevanta_binmeta",
    "codevanta_bridges",
    "codevanta_callgraph",
    "codevanta_certs",
    "codevanta_cfg",
    "codevanta_codesign",
    "codevanta_compare",
    "codevanta_coverage",
    "codevanta_crash",
    "codevanta_dataflow",
    "codevanta_debug",
    "codevanta_decompile",
    "codevanta_diff",
    "codevanta_disasm",
    "codevanta_dtb",
    "codevanta_dwarf",
    "codevanta_entropy",
    "codevanta_firmware_extract",
    "codevanta_frida",
    "codevanta_function_hash",
    "codevanta_functions",
    "codevanta_gpu",
    "codevanta_il2cpp",
    "codevanta_info",
    "codevanta_js_recover",
    "codevanta_jump_table",
    "codevanta_lldb_run",
    "codevanta_metadata",
    "codevanta_nav",
    "codevanta_nav_providers",
    "codevanta_obligations",
    "codevanta_pcap_fields",
    "codevanta_proto_decode",
    "codevanta_providers",
    "codevanta_rizin_functions",
    "codevanta_session_list",
    "codevanta_session_save",
    "codevanta_signal_sr",
    "codevanta_similarity",
    "codevanta_sqlite",
    "codevanta_strings",
    "codevanta_struct",
    "codevanta_symbolic",
    "codevanta_symbolic_solve",
    "codevanta_trace",
    "codevanta_uart_decode",
    "codevanta_unknowns",
    "codevanta_vtable",
    "codevanta_web_capture",
    "codevanta_web_inspect",
    "codevanta_xrefs",
]


def _payload(result: object) -> dict:
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")


def test_server_call_tool_returns_payload(elf64_text_path: Path) -> None:
    result = asyncio.run(
        build_server().call_tool("codevanta_info", {"path": str(elf64_text_path)})
    )
    payload = _payload(result)
    assert payload["format"] == "ELF"
    assert payload["architecture"] == "x86_64"


TEXT_ADDRESS = 0x401000


def _write_elf64(path: Path, code: bytes, *, text_address: int = TEXT_ADDRESS) -> Path:
    """Write a minimal ELF64 executable with one executable ``.text`` section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 0x40
    shstrtab_offset = (text_offset + len(code) + 7) & ~7
    shoff = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type = ET_EXEC
        62,            # e_machine = EM_X86_64
        1,             # e_version
        text_address,  # e_entry
        0,             # e_phoff
        shoff,         # e_shoff
        0,             # e_flags
        64,            # e_ehsize
        56,            # e_phentsize
        0,             # e_phnum
        64,            # e_shentsize
        3,             # e_shnum
        2,             # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # sh_type = SHT_PROGBITS
        6,              # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        text_address,   # sh_addr
        text_offset,    # sh_offset
        len(code),      # sh_size
        0,              # sh_link
        0,              # sh_info
        16,             # sh_addralign
        0,              # sh_entsize
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        7,                  # sh_name -> ".shstrtab"
        3,                  # sh_type = SHT_STRTAB
        0,                  # sh_flags
        0,                  # sh_addr
        shstrtab_offset,    # sh_offset
        len(shstrtab),      # sh_size
        0,
        0,
        1,
        0,
    )
    blob = bytearray(shoff + 3 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


@pytest.fixture
def call_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` contains ``call 0x401010; ret``."""
    return _write_elf64(tmp_path / "call.bin", bytes.fromhex("e80b000000c3"))


@pytest.fixture
def branchy_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample with ``test eax, eax; je +2; nop; nop; ret``."""
    return _write_elf64(tmp_path / "branchy.bin", bytes.fromhex("85c074029090c3"))


@pytest.fixture
def straight_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` is ``mov eax, 42; ret`` (one path)."""
    return _write_elf64(tmp_path / "straight.bin", bytes.fromhex("b82a000000c3"))


@pytest.fixture
def two_way_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample: ``test edi, edi; je +6; mov eax, 1; ret; mov eax, 2; ret``."""
    return _write_elf64(
        tmp_path / "two_way.bin",
        bytes.fromhex("85ff")        # 0x00: test edi, edi
        + bytes.fromhex("7406")      # 0x02: je 0x40100a
        + bytes.fromhex("b801000000")  # 0x04: mov eax, 1
        + bytes.fromhex("c3")        # 0x09: ret
        + bytes.fromhex("b802000000")  # 0x0a: mov eax, 2
        + bytes.fromhex("c3"),       # 0x0f: ret
    )


@pytest.fixture
def const_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` is ``mov rax, 5; ret``."""
    return _write_elf64(tmp_path / "const.bin", bytes.fromhex("48c7c005000000c3"))

def test_xrefs_reports_direct_call(call_elf_path: Path) -> None:
    payload = tools.xrefs(str(call_elf_path))

    assert payload["count"] >= 1
    assert payload["returned"] == len(payload["items"]) >= 1
    assert payload["truncated"] is False
    assert payload["scanned_bytes"] > 0
    item = payload["items"][0]
    assert item["kind"] == "call"
    assert item["from_address"] == "0x401000"
    assert item["to_address"] == "0x401010"
    assert item["evidence"]["source"] == "capstone.direct_call"


def test_xrefs_limit_truncates_items(call_elf_path: Path) -> None:
    payload = tools.xrefs(str(call_elf_path), limit=1)

    assert payload["count"] >= 1
    assert payload["returned"] == 1


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"limit": 0}, "limit"),
        ({"limit": tools.MAX_XREF_LIMIT + 1}, "limit"),
        ({"max_bytes": 0}, "max_bytes"),
        ({"max_bytes": tools.MAX_XREF_BYTES + 1}, "max_bytes"),
    ],
)
def test_xrefs_rejects_out_of_range_bounds(
    call_elf_path: Path, kwargs: dict[str, int], match: str
) -> None:
    with pytest.raises(AnalysisError, match=match):
        tools.xrefs(str(call_elf_path), **kwargs)


def test_cfg_splits_blocks(branchy_elf_path: Path) -> None:
    payload = tools.cfg(str(branchy_elf_path))

    assert payload["start"] == "0x401000"
    assert len(payload["blocks"]) >= 2
    assert payload["instruction_count"] >= 4
    assert payload["truncated"] is False
    assert payload["warnings"] == []
    assert payload["blocks"][0]["start"] == "0x401000"
    assert payload["blocks"][0]["terminator"] == "je"


def test_cfg_rejects_out_of_range_bounds(branchy_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.cfg(str(branchy_elf_path), max_instructions=0)
    with pytest.raises(AnalysisError, match="max_blocks"):
        tools.cfg(str(branchy_elf_path), max_blocks=0)


def test_cfg_unknown_function_is_an_analysis_error(branchy_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="not found"):
        tools.cfg(str(branchy_elf_path), function="no_such_function")


def test_callgraph_reports_nodes_and_edges(call_elf_path: Path) -> None:
    payload = tools.callgraph(str(call_elf_path))

    assert "nodes" in payload
    assert "edges" in payload
    assert payload["node_count"] == len(payload["nodes"]) >= 1
    assert payload["edge_count"] == len(payload["edges"]) >= 1
    assert payload["truncated"] is False
    edge = payload["edges"][0]
    assert edge["source"] == "0x401000"
    assert edge["target"] == "0x401010"
    assert edge["from_address"] == "0x401000"
    assert payload["evidence"]["source"] == "callgraph.direct_calls"


def test_server_call_tool_callgraph_returns_nodes_and_edges(
    call_elf_path: Path,
) -> None:
    result = asyncio.run(
        build_server().call_tool("codevanta_callgraph", {"path": str(call_elf_path)})
    )
    payload = _payload(result)

    assert "nodes" in payload
    assert "edges" in payload
    assert payload["edges"]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"limit_functions": 0}, "limit_functions"),
        ({"limit_functions": tools.MAX_CALLGRAPH_LIMIT + 1}, "limit_functions"),
        ({"limit_edges": 0}, "limit_edges"),
        ({"limit_edges": tools.MAX_CALLGRAPH_LIMIT + 1}, "limit_edges"),
    ],
)
def test_callgraph_rejects_out_of_range_bounds(
    call_elf_path: Path, kwargs: dict[str, int], match: str
) -> None:
    with pytest.raises(AnalysisError, match=match):
        tools.callgraph(str(call_elf_path), **kwargs)


def test_session_save_and_list(
    elf64_text_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "sessions.db"
    monkeypatch.setenv("CODEVANTA_DB", str(db_path))

    saved = tools.session_save(str(elf64_text_path), notes="mcp test")

    session = saved["session"]
    assert saved["db"] == str(db_path)
    assert session["session_id"]
    assert session["notes"] == "mcp test"
    assert session["format"] == "ELF"
    assert session["functions"] >= 1
    assert db_path.exists()

    listed = tools.session_list()

    assert listed["db"] == str(db_path)
    assert listed["count"] == 1
    assert [item["session_id"] for item in listed["items"]] == [session["session_id"]]


def test_session_save_respects_explicit_db(
    elf64_text_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CODEVANTA_DB", raising=False)
    db_path = tmp_path / "explicit.db"

    saved = tools.session_save(str(elf64_text_path), db=str(db_path))

    assert saved["db"] == str(db_path)
    assert tools.session_list(db=str(db_path), limit=5)["count"] == 1


def test_session_list_rejects_bad_limit(tmp_path: Path) -> None:
    db_path = str(tmp_path / "empty.db")
    with pytest.raises(SessionError, match="limit"):
        tools.session_list(db=db_path, limit=0)
    with pytest.raises(SessionError, match="limit"):
        tools.session_list(db=db_path, limit=tools.MAX_SESSION_LIMIT + 1)


DATA_ADDRESS = 0x402000


def _write_elf64_with_table(
    path: Path,
    table: bytes,
    *,
    code: bytes = b"\x90\x90\xc3",
) -> Path:
    """Write a minimal ELF64 executable with ``.text`` code and a ``.rodata`` table.

    Args:
        path: Destination file.
        table: Raw bytes placed at :data:`DATA_ADDRESS` in a non-executable
            ``.rodata`` section (``SHF_ALLOC`` only).
        code: Bytes of the executable ``.text`` section at :data:`TEXT_ADDRESS`.

    Returns:
        ``path``, written to disk.
    """
    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00"
    text_offset = 0x40
    rodata_offset = text_offset + len(code)
    shstrtab_offset = rodata_offset + len(table)
    shoff = (shstrtab_offset + len(shstrtab) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,              # e_type = ET_EXEC
        62,             # e_machine = EM_X86_64
        1,              # e_version
        TEXT_ADDRESS,   # e_entry
        0,              # e_phoff
        shoff,          # e_shoff
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        0,              # e_phnum
        64,             # e_shentsize
        4,              # e_shnum: null, .text, .rodata, .shstrtab
        3,              # e_shstrndx
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # sh_type = SHT_PROGBITS
        6,              # sh_flags = SHF_ALLOC | SHF_EXECINSTR
        TEXT_ADDRESS,   # sh_addr
        text_offset,    # sh_offset
        len(code),      # sh_size
        0,
        0,
        16,             # sh_addralign
        0,
    )
    rodata_section = struct.pack(
        "<IIQQQQIIQQ",
        7,              # sh_name -> ".rodata"
        1,              # sh_type = SHT_PROGBITS
        2,              # sh_flags = SHF_ALLOC (not executable)
        DATA_ADDRESS,   # sh_addr
        rodata_offset,  # sh_offset
        len(table),     # sh_size
        0,
        0,
        8,
        0,
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        15,                 # sh_name -> ".shstrtab"
        3,                  # sh_type = SHT_STRTAB
        0,
        0,
        shstrtab_offset,    # sh_offset
        len(shstrtab),      # sh_size
        0,
        0,
        1,
        0,
    )
    blob = bytearray(shoff + 4 * 64)
    blob[0:64] = header
    blob[text_offset : text_offset + len(code)] = code
    blob[rodata_offset : rodata_offset + len(table)] = table
    blob[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    blob[shoff + 64 : shoff + 128] = text_section
    blob[shoff + 128 : shoff + 192] = rodata_section
    blob[shoff + 192 : shoff + 256] = shstrtab_section
    path.write_bytes(bytes(blob))
    return path


def test_diff_reports_moved_entry_point(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("90c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("90c3"),
        text_address=TEXT_ADDRESS + 0x20,
    )

    payload = tools.diff(str(left), str(right))

    assert payload["identical"] is False
    assert payload["left_path"].endswith("left.bin")
    assert payload["right_path"].endswith("right.bin")
    assert [delta["address"] for delta in payload["functions_removed"]] == [
        "0x401000"
    ]
    assert [delta["address"] for delta in payload["functions_added"]] == [
        "0x401020"
    ]
    assert payload["functions_changed"] == []
    assert payload["sections_added"] == []
    assert payload["sections_removed"] == []
    assert payload["evidence"]["source"] == "binary_diff.structural"
    assert json.loads(json.dumps(payload)) == payload
    assert tools.diff(str(left), str(left), deep=True)["identical"] is True

    for kwargs in (
        {"max_functions": 0},
        {"max_functions": True},
        {"max_functions": tools.MAX_TOOL_LIMIT + 1},
    ):
        with pytest.raises(AnalysisError, match="max_functions"):
            tools.diff(str(left), str(right), **kwargs)
    with pytest.raises(AnalysisError, match="deep"):
        tools.diff(str(left), str(right), deep="yes")
    with pytest.raises(AnalysisError, match="file not found"):
        tools.diff(str(tmp_path / "missing.bin"), str(right))


def test_diff_semantic_pairs_a_moved_function(tmp_path: Path) -> None:
    """semantic=true turns a remove-plus-add pair into one changed entry."""
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("b82a000000c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("b82a000000c3"),
        text_address=TEXT_ADDRESS + 0x10,
    )

    structural = tools.diff(str(left), str(right))
    assert structural["functions_changed"] == []
    assert [delta["address"] for delta in structural["functions_removed"]] == [
        "0x401000"
    ]
    assert [delta["address"] for delta in structural["functions_added"]] == [
        "0x401010"
    ]
    assert "semantic" not in structural["evidence"]["extra"]

    payload = tools.diff(str(left), str(right), semantic=True)

    assert payload["identical"] is False
    assert payload["functions_added"] == []
    assert payload["functions_removed"] == []
    assert len(payload["functions_changed"]) == 1
    delta = payload["functions_changed"][0]
    assert delta["address"] == "0x401010"
    assert delta["left"]["address"] == "0x401000"
    assert delta["right"]["address"] == "0x401010"
    assert delta["similarity"] == pytest.approx(1.0)
    assert payload["evidence"]["extra"]["semantic"] is True
    assert (
        payload["evidence"]["extra"]["semantic_threshold"]
        == DEFAULT_SEMANTIC_THRESHOLD
    )
    assert json.loads(json.dumps(payload)) == payload


def test_diff_semantic_threshold_gates_pairing(tmp_path: Path) -> None:
    """A score under the floor leaves the structural add/remove verdict intact."""
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("90c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("9090c3"),
        text_address=TEXT_ADDRESS + 0x10,
    )

    # The shapes overlap at 2/3, which the default 0.9 floor refuses.
    strict = tools.diff(str(left), str(right), semantic=True)
    assert strict["functions_changed"] == []
    assert [delta["address"] for delta in strict["functions_removed"]] == [
        "0x401000"
    ]
    assert [delta["address"] for delta in strict["functions_added"]] == ["0x401010"]

    # Lowering the floor authorises the same pair, and the reported score is the
    # rounded value that cleared it.
    loose = tools.diff(str(left), str(right), semantic=True, threshold=0.5)
    assert loose["functions_added"] == []
    assert loose["functions_removed"] == []
    assert len(loose["functions_changed"]) == 1
    assert 0.5 <= loose["functions_changed"][0]["similarity"] < 1.0
    assert loose["evidence"]["extra"]["semantic_threshold"] == 0.5


def test_diff_validates_semantic_and_threshold(tmp_path: Path) -> None:
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("90c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("90c3"),
        text_address=TEXT_ADDRESS + 0x10,
    )

    for kwargs in ({"semantic": "yes"}, {"semantic": 1}, {"semantic": None}):
        with pytest.raises(AnalysisError, match="semantic"):
            tools.diff(str(left), str(right), **kwargs)  # type: ignore[arg-type]
    for kwargs in (
        {"threshold": 1.01},
        {"threshold": -0.01},
        {"threshold": 2},
        {"threshold": float("nan")},
        {"threshold": float("inf")},
        {"threshold": True},
        {"threshold": "0.9"},
        {"threshold": None},
    ):
        with pytest.raises(AnalysisError, match="threshold"):
            tools.diff(str(left), str(right), **kwargs)  # type: ignore[arg-type]

    # The floor is validated even when semantic mode is off, and both interval
    # endpoints are accepted.
    with pytest.raises(AnalysisError, match="threshold"):
        tools.diff(str(left), str(right), threshold=2.0)
    for edge in (0.0, 1.0):
        payload = tools.diff(
            str(left), str(right), semantic=True, threshold=edge
        )
        assert payload["evidence"]["extra"]["semantic_threshold"] == edge


def test_server_diff_schema_exposes_deep_semantic_threshold() -> None:
    listed = asyncio.run(build_server().list_tools())
    schema = next(
        tool for tool in listed if tool.name == "codevanta_diff"
    ).input_schema
    properties = schema["properties"]
    assert properties["deep"]["type"] == "boolean"
    assert properties["deep"]["default"] is False
    assert properties["semantic"]["type"] == "boolean"
    assert properties["semantic"]["default"] is False
    assert properties["threshold"]["type"] == "number"
    assert properties["threshold"]["default"] == DEFAULT_SEMANTIC_THRESHOLD
    assert schema["required"] == ["left", "right"]


def test_server_call_tool_diff_accepts_semantic_and_threshold(
    tmp_path: Path,
) -> None:
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("b82a000000c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("b82a000000c3"),
        text_address=TEXT_ADDRESS + 0x10,
    )

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_diff",
            {
                "left": str(left),
                "right": str(right),
                "deep": True,
                "semantic": True,
                "threshold": 0.5,
            },
        )
    )
    payload = _payload(result)
    assert payload["functions_added"] == []
    assert payload["functions_removed"] == []
    assert payload["functions_changed"][0]["similarity"] == pytest.approx(1.0)
    assert payload["evidence"]["extra"]["semantic_threshold"] == 0.5
    assert payload["evidence"]["extra"]["deep"] is True


def test_server_call_tool_diff_rejects_coerced_flag_values(
    tmp_path: Path,
) -> None:
    """The wrapper may not rewrite a flag: tools.diff has to see the raw value.

    ``deep=1``, ``semantic=1``, ``threshold=True`` and ``threshold="0.9"`` are
    documented as errors, so the MCP layer must not turn them into ``True`` /
    ``1.0`` / ``0.9`` first. ``call_tool`` raises the framework's ``ToolError``
    for an anticipated failure and the server turns exactly that text into
    ``is_error=True`` content, so the error still names the argument.
    """
    left = _write_elf64(tmp_path / "left.bin", bytes.fromhex("90c3"))
    right = _write_elf64(
        tmp_path / "right.bin",
        bytes.fromhex("9090c3"),
        text_address=TEXT_ADDRESS + 0x10,
    )
    base = {"left": str(left), "right": str(right)}
    server = build_server()

    for arguments, expected in (
        ({"deep": 1}, "deep must be a boolean"),
        ({"deep": "true"}, "deep must be a boolean"),
        ({"semantic": 1}, "semantic must be a boolean"),
        ({"semantic": 0}, "semantic must be a boolean"),
        ({"threshold": True}, "threshold must be a number"),
        ({"threshold": False}, "threshold must be a number"),
        ({"threshold": "0.9"}, "threshold must be a number"),
    ):
        with pytest.raises(ToolError, match=expected) as excinfo:
            asyncio.run(server.call_tool("codevanta_diff", base | arguments))
        assert "codevanta_diff" in str(excinfo.value)

    # The floor is checked in every mode, so a coerced boolean is refused even
    # with semantic off rather than becoming a silent 1.0 floor.
    with pytest.raises(ToolError, match="threshold must be a number"):
        asyncio.run(
            server.call_tool(
                "codevanta_diff", base | {"semantic": False, "threshold": True}
            )
        )

    # Real booleans and a real number still work, and an integer literal is a
    # number rather than a coercion, so it keeps the behaviour of tools.diff.
    same = asyncio.run(
        server.call_tool(
            "codevanta_diff",
            {"left": str(left), "right": str(left), "deep": True, "threshold": 1},
        )
    )
    assert _payload(same)["identical"] is True


def test_jump_table_decodes_absolute_and_relative_tables(tmp_path: Path) -> None:
    absolute = _write_elf64_with_table(
        tmp_path / "absolute.bin",
        struct.pack("<QQ", TEXT_ADDRESS, TEXT_ADDRESS + 2) + bytes(8),
    )
    relative = _write_elf64_with_table(
        tmp_path / "relative.bin",
        struct.pack("<ii", 0, 2),
    )

    payload = tools.jump_table(str(absolute), DATA_ADDRESS)

    assert payload["table_address"] == "0x402000"
    assert payload["entry_count"] == 2
    assert payload["pointer_size"] == 8
    assert payload["truncated"] is False
    assert [entry["target"] for entry in payload["entries"]] == [
        "0x401000",
        "0x401002",
    ]
    assert payload["evidence"]["source"] == "jump_table.pointer_array"
    assert json.loads(json.dumps(payload)) == payload

    offsets = tools.jump_table(
        str(relative),
        DATA_ADDRESS,
        mode="Relative",
        base=TEXT_ADDRESS,
    )

    assert offsets["pointer_size"] == 4
    assert [entry["target"] for entry in offsets["entries"]] == [
        "0x401000",
        "0x401002",
    ]
    assert offsets["evidence"]["source"] == "jump_table.relative_offsets"

    with pytest.raises(AnalysisError, match="base"):
        tools.jump_table(str(relative), DATA_ADDRESS, mode="relative")
    with pytest.raises(AnalysisError, match="mode"):
        tools.jump_table(str(absolute), DATA_ADDRESS, mode="sideways")
    with pytest.raises(AnalysisError, match="address"):
        tools.jump_table(str(absolute), True)
    with pytest.raises(AnalysisError, match="address"):
        tools.jump_table(str(absolute), -1)
    for entries in (0, True, tools.MAX_TOOL_LIMIT + 1, tools.MAX_JUMP_TABLE_ENTRIES + 1):
        with pytest.raises(AnalysisError, match="entries"):
            tools.jump_table(str(absolute), DATA_ADDRESS, entries=entries)
    with pytest.raises(AnalysisError, match="executable_only"):
        tools.jump_table(str(absolute), DATA_ADDRESS, executable_only="yes")
    with pytest.raises(AnalysisError, match="file not found"):
        tools.jump_table(str(tmp_path / "missing.bin"), DATA_ADDRESS)


def test_function_hash_matches_shape_not_bytes(tmp_path: Path) -> None:
    imm42 = _write_elf64(tmp_path / "imm42.bin", bytes.fromhex("b82a000000c3"))
    imm99 = _write_elf64(tmp_path / "imm99.bin", bytes.fromhex("b863000000c3"))
    narrow = _write_elf64(tmp_path / "narrow.bin", bytes.fromhex("90c3"))

    first = tools.function_hash(str(imm42), TEXT_ADDRESS)
    second = tools.function_hash(str(imm99), TEXT_ADDRESS)
    other = tools.function_hash(str(narrow), TEXT_ADDRESS, max_instructions=10)

    assert first["address"] == "0x401000"
    assert first["algorithm"] == "sha256"
    assert len(first["digest"]) == 64
    assert first["instruction_count"] == 2
    assert first["truncated"] is False
    assert first["evidence"]["source"] == "function_hash.normalized"
    assert first["digest"] == second["digest"]
    assert first["digest"] != other["digest"]
    assert json.loads(json.dumps(first)) == first

    with pytest.raises(AnalysisError, match="not inside an executable section"):
        tools.function_hash(str(imm42), 0)
    with pytest.raises(AnalysisError, match="address"):
        tools.function_hash(str(imm42), True)
    with pytest.raises(AnalysisError, match="address"):
        tools.function_hash(str(imm42), -1)
    for max_instructions in (0, True, tools.MAX_TOOL_LIMIT + 1):
        with pytest.raises(AnalysisError, match="max_instructions"):
            tools.function_hash(
                str(imm42),
                TEXT_ADDRESS,
                max_instructions=max_instructions,
            )
    with pytest.raises(AnalysisError, match="file not found"):
        tools.function_hash(str(tmp_path / "missing.bin"), TEXT_ADDRESS)

def test_similarity_scores_same_file_and_address_as_one(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "similarity.bin", bytes.fromhex("b82a000000c3"))

    payload = tools.similarity(str(binary), TEXT_ADDRESS, str(binary), TEXT_ADDRESS)

    assert payload["score"] == 1.0
    assert payload["shared"] == 2
    assert payload["left_total"] == 2
    assert payload["right_total"] == 2
    assert payload["union"] == 2
    assert payload["warnings"] == []
    assert payload["evidence"]["source"] == "function_hash.similarity"
    assert payload["evidence"]["method"] == "token_multiset"
    assert payload["evidence"]["confidence"] == "medium"
    assert payload["evidence"]["address"] == "0x401000"
    assert json.loads(json.dumps(payload)) == payload

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_similarity",
            {
                "path_a": str(binary),
                "address_a": TEXT_ADDRESS,
                "path_b": str(binary),
                "address_b": TEXT_ADDRESS,
            },
        )
    )
    assert _payload(result)["score"] == 1.0


def test_similarity_masks_immediates_and_validates_arguments(tmp_path: Path) -> None:
    imm42 = _write_elf64(tmp_path / "sim_imm42.bin", bytes.fromhex("b82a000000c3"))
    imm99 = _write_elf64(tmp_path / "sim_imm99.bin", bytes.fromhex("b863000000c3"))
    narrow = _write_elf64(tmp_path / "sim_narrow.bin", bytes.fromhex("90c3"))

    # Only the masked immediate differs, so the shape score is still 1.0.
    recompiled = tools.similarity(
        str(imm42), TEXT_ADDRESS, str(imm99), TEXT_ADDRESS
    )
    assert recompiled["score"] == 1.0

    # ``nop; ret`` shares only ``ret`` with ``mov eax, #; ret``: 1 of 3 tokens.
    partial = tools.similarity(str(imm42), TEXT_ADDRESS, str(narrow), TEXT_ADDRESS)
    assert partial["score"] == 0.3333
    assert partial["shared"] == 1
    assert partial["union"] == 3
    assert partial["evidence"]["extra"]["right_address"] == "0x401000"

    # A one-instruction budget truncates both sides, so only prefixes compare.
    truncated = tools.similarity(
        str(imm42),
        TEXT_ADDRESS,
        str(imm42),
        TEXT_ADDRESS,
        max_instructions=1,
    )
    assert truncated["score"] == 1.0
    assert len(truncated["warnings"]) == 2

    for side in ("address_a", "address_b"):
        for bad in (True, -1):
            with pytest.raises(AnalysisError, match=side):
                tools.similarity(
                    str(imm42),
                    bad if side == "address_a" else TEXT_ADDRESS,
                    str(imm42),
                    bad if side == "address_b" else TEXT_ADDRESS,
                )
    for max_instructions in (0, True, tools.MAX_TOOL_LIMIT + 1):
        with pytest.raises(AnalysisError, match="max_instructions"):
            tools.similarity(
                str(imm42),
                TEXT_ADDRESS,
                str(imm42),
                TEXT_ADDRESS,
                max_instructions=max_instructions,
            )
    with pytest.raises(AnalysisError, match="file not found"):
        tools.similarity(
            str(tmp_path / "missing.bin"), TEXT_ADDRESS, str(imm42), TEXT_ADDRESS
        )
    with pytest.raises(AnalysisError, match="file not found"):
        tools.similarity(
            str(imm42), TEXT_ADDRESS, str(tmp_path / "missing.bin"), TEXT_ADDRESS
        )
    with pytest.raises(AnalysisError, match="not inside an executable section"):
        tools.similarity(str(imm42), 0, str(imm42), TEXT_ADDRESS)


#: ``mov rax, [rdi + 0x10]``, ``mov [rdi + 0x18], rbx``, ``mov ecx, [rdi + 0x20]``, ``ret``.
STRUCT_CODE = bytes.fromhex("488b471048895f188b4f20c3")


def test_struct_recovers_fields_from_register_operands(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "struct.bin", STRUCT_CODE)

    payload = tools.struct(str(binary), TEXT_ADDRESS)

    assert payload["address"] == "0x401000"
    assert payload["instruction_count"] == 4
    assert payload["field_count"] == 3
    assert payload["max_fields"] == 64
    assert payload["truncated"] is False
    assert payload["include_stack"] is False
    assert [field["offset"] for field in payload["fields"]] == [
        "0x10",
        "0x18",
        "0x20",
    ]
    assert [
        (field["width"], field["read_count"], field["write_count"])
        for field in payload["fields"]
    ] == [(8, 1, 0), (8, 0, 1), (4, 1, 0)]
    assert payload["alignment"] == 8
    assert payload["array_groups"] == []
    assert payload["evidence"]["source"] == "type_recovery.suggestion"
    assert payload["evidence"]["confidence"] == "medium"
    assert json.loads(json.dumps(payload)) == payload

    # Without an address or function the entry point is the sweep start.
    assert tools.struct(str(binary))["address"] == "0x401000"


def test_struct_caps_fields_and_validates_arguments(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "struct_limits.bin", STRUCT_CODE)

    capped = tools.struct(str(binary), TEXT_ADDRESS, max_fields=2)

    assert capped["max_fields"] == 2
    assert capped["field_count"] == 2
    assert capped["truncated"] is True
    assert [field["offset"] for field in capped["fields"]] == ["0x10", "0x18"]
    assert capped["alignment"] == 8

    # ``mov rax, [rbp + 8]`` is a stack slot, reported only on request.
    stack_binary = _write_elf64(tmp_path / "stack.bin", bytes.fromhex("488b4508c3"))
    assert tools.struct(str(stack_binary), TEXT_ADDRESS)["field_count"] == 0
    stack = tools.struct(str(stack_binary), TEXT_ADDRESS, include_stack=True)
    assert [(field["offset"], field["width"]) for field in stack["fields"]] == [
        ("0x8", 8)
    ]

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_struct",
            {"path": str(binary), "address": TEXT_ADDRESS, "max_fields": 2},
        )
    )
    assert _payload(result)["field_count"] == 2

    with pytest.raises(AnalysisError, match="address"):
        tools.struct(str(binary), -1)
    with pytest.raises(AnalysisError, match="address"):
        tools.struct(str(binary), True)
    with pytest.raises(AnalysisError, match="function"):
        tools.struct(str(binary), function=7)
    with pytest.raises(AnalysisError, match="not found"):
        tools.struct(str(binary), function="nope")
    for max_instructions in (0, True, MAX_MAX_INSTRUCTIONS + 1):
        with pytest.raises(AnalysisError, match="max_instructions"):
            tools.struct(
                str(binary), TEXT_ADDRESS, max_instructions=max_instructions
            )
    for max_fields in (0, True, MAX_MAX_FIELDS + 1):
        with pytest.raises(AnalysisError, match="max_fields"):
            tools.struct(str(binary), TEXT_ADDRESS, max_fields=max_fields)
    with pytest.raises(AnalysisError, match="include_stack"):
        tools.struct(str(binary), TEXT_ADDRESS, include_stack="yes")
    with pytest.raises(AnalysisError, match="not inside an executable section"):
        tools.struct(str(binary), 0)
    with pytest.raises(AnalysisError, match="file not found"):
        tools.struct(str(tmp_path / "missing.bin"), TEXT_ADDRESS)


# --- saved dynamic-session traces ---------------------------------------------


#: The two addresses the hand-written captures hit: inside the fixture ``.text``.
TRACE_HIT_ADDRESSES = (TEXT_ADDRESS, TEXT_ADDRESS + 2)

#: ``mov eax, 42; ret`` -- long enough for both hits to land in one candidate.
TRACE_CODE = bytes.fromhex("b82a000000c3")


def _gdb_trace_text() -> str:
    """Return a gdb capture as the generated session script prints it: two hits.

    One ``HIT`` line carries a ``BACKTRACE`` with two frames, the other carries
    none, and gdb's own noise (``Breakpoint 1 at``, ``Inferior 1 exited``,
    ``DONE``) wraps the capture exactly as a saved log does.
    """
    first, second = TRACE_HIT_ADDRESSES
    frames = f"#0  0x{first:016x} in main ()\n#1  0x{first + 0x10:016x} in ?? ()"
    lines = [
        f"Breakpoint 1 at 0x{first:x}",
        f"HIT 0x{first:x} pc=0x{first:x} sp=0x7ffffffde0 rip=0x{first:x} rax=0x1",
        "BACKTRACE",
        frames,
        f"HIT 0x{second:x} pc=0x{second:x} sp=0x7ffffffdd0 rip=0x{second:x} rax=0x2",
        "[Inferior 1 (process 4321) exited normally]",
        "DONE 2 hits",
    ]
    return "\n".join(lines) + "\n"


def _frida_trace_text() -> str:
    """Return the JSON lines a generated Frida hook sends for the same two hits."""
    return (
        "\n".join(
            json.dumps(
                {
                    "hit": index,
                    "address": hex(address),
                    "tid": 4321,
                    "args": ["0x1", "0x2"],
                }
            )
            for index, address in enumerate(TRACE_HIT_ADDRESSES, start=1)
        )
        + "\n"
    )


def test_trace_replays_a_hand_written_gdb_capture(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_gdb.bin", TRACE_CODE)
    capture = tmp_path / "session.gdb.log"
    capture.write_text(_gdb_trace_text(), encoding="utf-8")

    payload = tools.trace(str(binary), str(capture))

    assert payload["provider"] == "gdb"
    assert payload["provider_resolved"] == "gdb"
    assert payload["total_hits"] == 2
    assert payload["truncated"] is False
    assert payload["warnings"] == []
    assert payload["path"] == str(binary)
    assert payload["trace_path"] == str(capture)
    first, second = payload["hits"]
    assert [first["address"], second["address"]] == [
        f"0x{address:x}" for address in TRACE_HIT_ADDRESSES
    ]
    assert first["kind"] == "breakpoint"
    assert first["function"] == f"0x{TEXT_ADDRESS:x}"
    assert first["backtrace"] == [f"0x{TEXT_ADDRESS:x}", f"0x{TEXT_ADDRESS + 0x10:x}"]
    assert second["backtrace"] == []
    assert payload["unique_addresses"] == [
        f"0x{address:x}" for address in TRACE_HIT_ADDRESSES
    ]
    assert payload["function_coverage"] == {f"0x{TEXT_ADDRESS:x}": 2}
    assert payload["evidence"]["method"] == "parse_gdb_trace"
    assert payload["evidence"]["extra"]["provider"] == "gdb"
    # Every other tool returns JSON-safe values; so must this one.
    assert json.loads(json.dumps(payload)) == payload


def test_trace_detects_the_provider_off_the_file(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_frida.bin", TRACE_CODE)
    capture = tmp_path / "session.frida.jsonl"
    capture.write_text(_frida_trace_text(), encoding="utf-8")

    payload = tools.trace(str(binary), str(capture))

    assert payload["provider"] == "frida"
    assert payload["provider_resolved"] == "frida"
    assert payload["total_hits"] == 2
    assert payload["evidence"]["method"] == "parse_frida_trace"
    hit = payload["hits"][0]
    assert hit["kind"] == "message"
    assert hit["function"] == f"0x{TEXT_ADDRESS:x}"
    # A Frida message carries no register dump or stack, only tid plus args.
    assert hit["registers"] == {"tid": 4321, "arg0": 1, "arg1": 2}
    assert hit["backtrace"] == []


def test_trace_rejects_a_provider_that_contradicts_the_file(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_mismatch.bin", TRACE_CODE)
    gdb_capture = tmp_path / "session.gdb.log"
    gdb_capture.write_text(_gdb_trace_text(), encoding="utf-8")
    frida_capture = tmp_path / "session.jsonl"
    frida_capture.write_text(_frida_trace_text(), encoding="utf-8")

    with pytest.raises(AnalysisError, match="provider mismatch") as excinfo:
        tools.trace(str(binary), str(gdb_capture), provider="frida")
    assert "gdb" in str(excinfo.value)

    with pytest.raises(AnalysisError, match="provider mismatch"):
        tools.trace(str(binary), str(frida_capture), provider="gdb")

    # An explicit provider that agrees with the file is honoured.
    agreed = tools.trace(str(binary), str(gdb_capture), provider="gdb")
    assert agreed["provider_resolved"] == "gdb"

    with pytest.raises(AnalysisError, match="provider must be one of"):
        tools.trace(str(binary), str(gdb_capture), provider="lldb")


def test_trace_reports_a_missing_or_unusable_trace_file(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_missing.bin", TRACE_CODE)

    with pytest.raises(AnalysisError, match="trace file not found") as excinfo:
        tools.trace(str(binary), str(tmp_path / "missing.gdb.log"))
    assert "missing.gdb.log" in str(excinfo.value)

    with pytest.raises(AnalysisError, match="not a regular trace file"):
        tools.trace(str(binary), str(tmp_path))

    with pytest.raises(AnalysisError, match="trace_path"):
        tools.trace(str(binary), "")

    # The binary keeps its own, already-established wording.
    with pytest.raises(AnalysisError, match="file not found"):
        tools.trace(str(tmp_path / "missing.bin"), str(tmp_path / "missing.gdb.log"))


def test_trace_refuses_to_guess_an_unrecognisable_capture(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_noise.bin", TRACE_CODE)
    capture = tmp_path / "noise.log"
    capture.write_text("nothing here\nnor here\n", encoding="utf-8")

    with pytest.raises(AnalysisError, match="cannot tell"):
        tools.trace(str(binary), str(capture))

    # Named explicitly, the same file parses and simply reports no hits.
    payload = tools.trace(str(binary), str(capture), provider="gdb")
    assert payload["provider_resolved"] == "gdb"
    assert payload["total_hits"] == 0
    assert payload["hits"] == []


def test_trace_bounds_the_hits_it_keeps(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_cap.bin", TRACE_CODE)
    capture = tmp_path / "session.gdb.log"
    capture.write_text(_gdb_trace_text(), encoding="utf-8")

    capped = tools.trace(str(binary), str(capture), max_hits=1)

    assert capped["total_hits"] == 2
    assert len(capped["hits"]) == 1
    assert capped["truncated"] is True
    assert any("hit limit 1" in warning for warning in capped["warnings"])

    for max_hits in (0, True, tools.MAX_TRACE_HITS + 1):
        with pytest.raises(AnalysisError, match="max_hits"):
            tools.trace(str(binary), str(capture), max_hits=max_hits)


def test_trace_bounds_the_bytes_it_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = _write_elf64(tmp_path / "trace_bytes.bin", TRACE_CODE)
    capture = tmp_path / "session.gdb.log"
    capture.write_text(_gdb_trace_text(), encoding="utf-8")
    monkeypatch.setattr(tools, "MAX_TRACE_BYTES", 40)

    payload = tools.trace(str(binary), str(capture), provider="gdb")

    # The budget stops inside the first line, so nothing parses -- and the cut is
    # reported rather than handed to the parser as a half ``HIT`` line.
    assert payload["truncated"] is True
    assert payload["hits"] == []
    assert any(
        "truncated to the first 40 byte" in warning for warning in payload["warnings"]
    )


def test_trace_tool_is_registered_with_a_stable_schema() -> None:
    listed = {tool.name: tool for tool in asyncio.run(build_server().list_tools())}
    schema = listed["codevanta_trace"].input_schema

    assert schema["required"] == ["path", "trace_path"]
    assert set(schema["properties"]) == {"path", "trace_path", "provider", "max_hits"}
    assert schema["properties"]["provider"]["enum"] == ["auto", "gdb", "frida"]
    assert schema["properties"]["provider"]["default"] == "auto"
    assert schema["properties"]["max_hits"]["default"] is None


def test_server_call_tool_trace_returns_the_report(tmp_path: Path) -> None:
    binary = _write_elf64(tmp_path / "trace_server.bin", TRACE_CODE)
    capture = tmp_path / "session.jsonl"
    capture.write_text(_frida_trace_text(), encoding="utf-8")

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_trace",
            {"path": str(binary), "trace_path": str(capture), "provider": "auto"},
        )
    )

    payload = _payload(result)
    assert payload["provider_resolved"] == "frida"
    assert payload["total_hits"] == 2
    assert payload["function_coverage"] == {f"0x{TEXT_ADDRESS:x}": 2}

    # A wrong provider reaches the client as a ToolError naming the tool.
    with pytest.raises(ToolError, match="provider mismatch"):
        asyncio.run(
            build_server().call_tool(
                "codevanta_trace",
                {"path": str(binary), "trace_path": str(capture), "provider": "gdb"},
            )
        )


# --- bind host normalisation, loopback guard and SDK hardening -----------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("[::1]", "::1"),
        ("  [::1]  ", "::1"),
        ("localhost", "127.0.0.1"),
        ("LOCALHOST", "127.0.0.1"),
        (" LocalHost ", "127.0.0.1"),
        ("127.0.0.1", "127.0.0.1"),
        (" 127.0.0.2 ", "127.0.0.2"),
        ("::1", "::1"),
        ("0.0.0.0", "0.0.0.0"),
        ("localhost.evil.com", "localhost.evil.com"),
        ("", ""),
        ("   ", ""),
        # A lone bracket or an empty pair is not an IPv6 literal and is left alone.
        ("[::1", "[::1"),
        ("[]", "[]"),
    ],
)
def test_normalise_host_drops_brackets_and_maps_localhost(host: str, expected: str) -> None:
    assert mcp_server.normalise_host(host) == expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("127.0.0.2", True),
        ("127.255.255.254", True),
        ("  127.0.0.1  ", True),
        ("0.0.0.0", False),
        ("::", False),
        ("[::]", False),
        ("localhost.evil.com", False),
        ("127.0.0.1.evil.com", False),
        ("example.com", False),
        ("[::1", False),
        ("", False),
        ("   ", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert mcp_server.is_loopback_host(host) is expected


def test_is_loopback_host_rejects_non_strings() -> None:
    assert mcp_server.is_loopback_host(None) is False  # type: ignore[arg-type]
    assert mcp_server.is_loopback_host(127) is False  # type: ignore[arg-type]


def test_the_guard_covers_every_host_the_sdk_hardens() -> None:
    """Our loopback rule must be a superset of the SDK's three literal hosts."""
    assert all(mcp_server.is_loopback_host(host) for host in mcp_server.SDK_HARDENED_HOSTS)


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "127.0.0.2", "::1", "[::1]", " 127.0.0.1 "],
)
def test_transport_security_always_lists_the_real_bind_address(host: str) -> None:
    settings = mcp_server.transport_security(host)

    assert isinstance(settings, TransportSecuritySettings)
    assert settings.enable_dns_rebinding_protection is True
    bind_host = mcp_server.normalise_host(host)
    authority = f"[{bind_host}]" if ":" in bind_host else bind_host
    assert authority in settings.allowed_hosts
    assert f"{authority}:*" in settings.allowed_hosts
    assert f"http://{authority}" in settings.allowed_origins
    assert f"http://{authority}:*" in settings.allowed_origins


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "example.com", "8.8.8.8"])
def test_transport_security_stays_off_for_a_remote_bind(host: str) -> None:
    assert mcp_server.transport_security(host) is None


def _rejection_status(settings: TransportSecuritySettings, host: str, origin: str | None = None):
    """Run the SDK's own middleware for one request; return the status or ``None``.

    This is the check the SDK applies to every HTTP request, so ``None`` here
    means the ``Host``/``Origin`` headers really would have been accepted.
    """
    headers = [(b"host", host.encode())]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    request = Request({"type": "http", "method": "GET", "path": "/sse", "headers": headers})
    response = asyncio.run(TransportSecurityMiddleware(settings).validate_request(request))
    return None if response is None else response.status_code


def test_127_0_0_2_is_hardened_not_just_accepted() -> None:
    """The finding: the SDK's own detection skips 127.0.0.2, so ``run`` passes settings."""
    assert mcp_server.normalise_host("127.0.0.2") not in mcp_server.SDK_HARDENED_HOSTS
    settings = mcp_server.transport_security("127.0.0.2")
    assert settings is not None

    assert _rejection_status(settings, "127.0.0.2:8000") is None
    assert _rejection_status(settings, "127.0.0.2:8000", "http://127.0.0.2:8000") is None
    # A rebinding page cannot reach the server under a foreign name or origin.
    assert _rejection_status(settings, "attacker.example:8000") == 421
    assert _rejection_status(settings, "127.0.0.2:8000", "http://attacker.example") == 403


def test_bracketed_ipv6_settings_use_the_bracketed_authority() -> None:
    settings = mcp_server.transport_security("[::1]")

    assert settings is not None
    assert _rejection_status(settings, "[::1]:8000") is None
    assert _rejection_status(settings, "[::1]:8000", "http://[::1]:8000") is None
    assert _rejection_status(settings, "attacker.example:8000") == 421


class _RecordingServer:
    """Stand-in for :class:`MCPServer` that records how :func:`run` calls it."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


@pytest.fixture()
def recording_server(monkeypatch: pytest.MonkeyPatch) -> _RecordingServer:
    """Replace ``build_server`` so ``run`` records a call instead of binding."""
    server = _RecordingServer()
    monkeypatch.setattr(mcp_server, "build_server", lambda: server)
    return server


def test_run_stdio_delegates_to_the_server(recording_server: _RecordingServer) -> None:
    mcp_server.run("stdio")

    assert recording_server.calls == [{"transport": "stdio"}]


@pytest.mark.parametrize("transport", ["bogus", "http", "", "sse ", "STDIO"])
def test_run_rejects_an_unknown_transport(
    transport: str, recording_server: _RecordingServer
) -> None:
    with pytest.raises(AnalysisError, match="transport"):
        mcp_server.run(transport)

    assert recording_server.calls == []


@pytest.mark.parametrize("port", [True, False, -1, 70000, 65536, "8000", 80.5])
def test_run_rejects_an_invalid_port(port: object, recording_server: _RecordingServer) -> None:
    with pytest.raises(AnalysisError, match="port"):
        mcp_server.run("sse", port=port)  # type: ignore[arg-type]

    assert recording_server.calls == []


@pytest.mark.parametrize("host", ["   ", "", "[]"])
def test_run_rejects_a_host_that_normalises_to_nothing(
    host: str, recording_server: _RecordingServer
) -> None:
    with pytest.raises(AnalysisError):
        mcp_server.run("sse", host=host, port=0)

    assert recording_server.calls == []


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "8.8.8.8", "example.com", "localhost.evil.com"])
def test_run_refuses_a_remote_host_without_allow_remote(
    host: str, recording_server: _RecordingServer
) -> None:
    with pytest.raises(AnalysisError, match="allow_remote"):
        mcp_server.run("sse", host=host, port=0)

    assert recording_server.calls == []


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_run_allows_a_remote_host_when_allow_remote_is_set(
    transport: str, recording_server: _RecordingServer
) -> None:
    mcp_server.run(transport, host="0.0.0.0", port=0, allow_remote=True)

    assert recording_server.calls == [
        {"transport": transport, "host": "0.0.0.0", "port": 0, "transport_security": None}
    ]


@pytest.mark.parametrize("host", ["127.0.0.2", "localhost", "[::1]", " 127.0.0.1 "])
def test_run_passes_the_normalised_host_with_hardening(
    host: str, recording_server: _RecordingServer
) -> None:
    mcp_server.run("sse", host=host, port=0)

    assert len(recording_server.calls) == 1
    call = recording_server.calls[0]
    assert call["host"] == mcp_server.normalise_host(host)
    assert call["port"] == 0
    settings = call["transport_security"]
    assert isinstance(settings, TransportSecuritySettings)
    assert settings.enable_dns_rebinding_protection is True


def test_entropy_reports_sections_with_evidence(elf64_text_path: Path) -> None:
    payload = tools.entropy(str(elf64_text_path))

    assert payload["threshold"] == 7.2
    assert payload["section_count"] == len(payload["sections"]) >= 1
    text = next(s for s in payload["sections"] if s["name"] == ".text")
    assert text["entropy"] is not None
    assert text["evidence"]["source"] == "entropy.section"
    assert isinstance(payload["packed_candidates"], list)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"threshold": 0.0}, "threshold"),
        ({"threshold": 8.5}, "threshold"),
        ({"threshold": -1.0}, "threshold"),
        ({"max_sample_bytes": 0}, "max_sample_bytes"),
        ({"max_sample_bytes": -1}, "max_sample_bytes"),
    ],
)
def test_entropy_rejects_out_of_range_bounds(
    elf64_text_path: Path, kwargs: dict[str, object], match: str
) -> None:
    with pytest.raises(AnalysisError, match=match):
        tools.entropy(str(elf64_text_path), **kwargs)  # type: ignore[arg-type]


def test_analyze_include_flags_add_phase2_sections(call_elf_path: Path) -> None:
    base = tools.analyze(str(call_elf_path))
    assert "xrefs" not in base
    assert "cfg" not in base
    assert "callgraph" not in base

    payload = tools.analyze(str(call_elf_path), include_xrefs=True, include_cfg=True)
    assert payload["xrefs"]["count"] >= 1  # the fixture calls 0x401010
    assert "blocks" in payload["cfg"] or "block_count" in payload["cfg"]
    assert "callgraph" not in payload  # still opt-in per flag


def test_server_call_tool_entropy_and_analyze_flags(elf64_text_path: Path) -> None:
    result = asyncio.run(
        build_server().call_tool("codevanta_entropy", {"path": str(elf64_text_path)})
    )
    payload = _payload(result)
    assert payload["section_count"] >= 1

    result = asyncio.run(
        build_server().call_tool(
            "codevanta_analyze",
            {"path": str(elf64_text_path), "include_xrefs": True},
        )
    )
    payload = _payload(result)
    assert "xrefs" in payload




# ---------------------------------------------------------------------------

#: ``mov rax, rdi; add rax, rsi; ret`` -- one block, two argument reads.
DECOMPILE_CODE = bytes.fromhex("4889f84801f0c3")


@pytest.fixture
def decompile_elf_path(tmp_path: Path) -> Path:
    """ELF64 sample whose ``.text`` is a one-block, two-argument straight line."""
    return _write_elf64(tmp_path / "decompile.bin", DECOMPILE_CODE)


def _external_backend() -> str | None:
    """Return the name of an installed external backend, or ``None``."""
    probes = {probe.name: probe for probe in available_backends()}
    for name in ("ghidra", "angr"):
        if probes[name].available:
            return name
    return None


def test_decompile_returns_backend_text_and_blocks(decompile_elf_path: Path) -> None:
    installed = _external_backend()
    if installed is not None:
        pytest.skip(f"the {installed} backend is installed, so 'auto' is not native")

    payload = tools.decompile(str(decompile_elf_path), 0x401000)

    assert payload["backend"] == "native"
    assert payload["language"] == "c"
    assert Path(payload["path"]) == decompile_elf_path
    assert payload["address"] == "0x401000"
    assert payload["blocks"] == 1
    assert "sub_401000(" in payload["text"]
    assert "mov rax, rdi" in payload["text"]
    assert "blocks: 1" in payload["text"]
    assert payload["evidence"]["source"] == "decompile.pseudo_c"
    # A fallback is never silent: both skipped backends are named, in order.
    assert len(payload["warnings"]) == 2
    assert "ghidra" in payload["warnings"][0]
    assert "angr" in payload["warnings"][1]


def test_decompile_native_backend_is_explicit_and_needs_no_fallback(
    decompile_elf_path: Path,
) -> None:
    payload = tools.decompile(str(decompile_elf_path), 0x401000, backend="native")

    assert payload["backend"] == "native"
    assert payload["warnings"] == []
    assert payload["blocks"] == 1


def test_decompile_angr_backend_errors_when_it_is_missing(
    decompile_elf_path: Path,
) -> None:
    probes = {probe.name: probe for probe in available_backends()}
    if probes["angr"].available:
        pytest.skip("the angr backend is installed in this environment")

    with pytest.raises(AnalysisError) as excinfo:
        tools.decompile(str(decompile_elf_path), 0x401000, backend="angr")

    message = str(excinfo.value)
    assert "angr" in message
    assert "backend" in message
    # Never a bare ImportError leaking out of the provider layer.
    assert not isinstance(excinfo.value, ImportError)


def test_decompile_rejects_an_unknown_backend(decompile_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="backend"):
        tools.decompile(str(decompile_elf_path), 0x401000, backend="radare2")


def test_decompile_rejects_an_invalid_address(decompile_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="address"):
        tools.decompile(str(decompile_elf_path), -1)

    with pytest.raises(AnalysisError, match="address"):
        tools.decompile(str(decompile_elf_path), True)  # type: ignore[arg-type]

    with pytest.raises(AnalysisError, match="0x999000"):
        tools.decompile(str(decompile_elf_path), 0x999000)


def test_decompile_rejects_out_of_range_budgets(decompile_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="max_instructions"):
        tools.decompile(str(decompile_elf_path), 0x401000, max_instructions=0)

    with pytest.raises(AnalysisError, match="max_blocks"):
        tools.decompile(str(decompile_elf_path), 0x401000, max_blocks=0)


def test_decompile_tool_is_registered_with_a_stable_schema() -> None:
    listed = {tool.name: tool for tool in asyncio.run(build_server().list_tools())}
    schema = listed["codevanta_decompile"].input_schema

    assert schema["required"] == ["path", "address"]
    assert set(schema["properties"]) == {
        "path",
        "address",
        "backend",
        "max_instructions",
        "max_blocks",
    }
    assert schema["properties"]["backend"]["default"] == "auto"
    assert schema["properties"]["backend"]["type"] == "string"
    assert schema["properties"]["address"]["type"] == "integer"


def test_server_call_tool_decompile_returns_a_rendering(
    decompile_elf_path: Path,
) -> None:
    result = asyncio.run(
        build_server().call_tool(
            "codevanta_decompile",
            {
                "path": str(decompile_elf_path),
                "address": 0x401000,
                "backend": "native",
            },
        )
    )

    payload = _payload(result)
    assert payload["backend"] == "native"
    assert payload["text"].strip()
    assert payload["blocks"] >= 1


def test_server_call_tool_decompile_surfaces_an_unavailable_backend(
    decompile_elf_path: Path,
) -> None:
    probes = {probe.name: probe for probe in available_backends()}
    if probes["angr"].available:
        pytest.skip("the angr backend is installed in this environment")

    with pytest.raises(ToolError, match="angr") as excinfo:
        asyncio.run(
            build_server().call_tool(
                "codevanta_decompile",
                {
                    "path": str(decompile_elf_path),
                    "address": 0x401000,
                    "backend": "angr",
                },
            )
        )

    assert "codevanta_decompile" in str(excinfo.value)


def test_symbolic_explores_a_straight_line_as_one_path(straight_elf_path: Path) -> None:
    payload = tools.symbolic(str(straight_elf_path), TEXT_ADDRESS)

    assert payload["explorer"] == "unicorn"
    assert payload["architecture"] == "x86_64"
    assert payload["paths"] == 1
    assert payload["complete"] is True
    assert payload["return_values"] == ["0x2a"]
    entry = payload["entries"][0]
    assert entry["stopped_reason"] == "return"
    assert entry["return_value"] == "0x2a"
    assert entry["decisions"] == []
    assert entry["seeded_branches"] == 0
    assert payload["evidence"]["source"] == "symbolic.unicorn"
    assert payload["evidence"]["method"] == "branch_decision_replay"
    assert payload["path"] == str(straight_elf_path)
    assert payload["address_resolved"] == "0x401000"
    # Every other tool returns JSON-safe values; so must this one.
    assert json.loads(json.dumps(payload)) == payload


def test_symbolic_labels_seeded_directions_as_assumptions(two_way_elf_path: Path) -> None:
    payload = tools.symbolic(str(two_way_elf_path), TEXT_ADDRESS, max_steps=2000)

    # Both sides of the one conditional are reported, and only one was real.
    assert payload["paths"] == 2
    assert {entry["decisions"][0]["basis"] for entry in payload["entries"]} == {
        "observed",
        "seeded",
    }
    assert payload["return_values"] == ["0x2", "0x1"]

    seeded = next(entry for entry in payload["entries"] if entry["seeded_branches"])
    decision = seeded["decisions"][0]
    assert decision["mnemonic"] == "je"
    assert "not proven" in decision["note"]
    assert any("not proven" in warning for warning in seeded["warnings"])

    # The evidence says what was observed versus what was only assumed.
    assert payload["evidence"]["confidence"] == "low"
    assert payload["evidence"]["extra"]["observed_branches"] == 1
    assert payload["evidence"]["extra"]["seeded_branches"] == 1
    assert any(
        "no constraint was solved" in assumption
        for assumption in payload["evidence"]["extra"]["assumptions"]
    )


def test_symbolic_rejects_bad_addresses_and_zero_budgets(straight_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="address must be non-negative"):
        tools.symbolic(str(straight_elf_path), -1)
    with pytest.raises(AnalysisError, match="not mapped by any section"):
        tools.symbolic(str(straight_elf_path), 0x700000)
    with pytest.raises(AnalysisError, match="max_paths must be between 1 and"):
        tools.symbolic(str(straight_elf_path), TEXT_ADDRESS, max_paths=0)
    with pytest.raises(AnalysisError, match="max_steps must be between 1 and"):
        tools.symbolic(str(straight_elf_path), TEXT_ADDRESS, max_steps=0)


def test_dataflow_recovers_definitions_and_constants(const_elf_path: Path) -> None:
    payload = tools.dataflow(str(const_elf_path), TEXT_ADDRESS)

    assert payload["address"] == "0x401000"
    assert payload["definitions"] == [
        {
            "address": "0x401000",
            "register": "rax",
            "kind": "const",
            "value": 5,
            "source_register": None,
        }
    ]
    assert payload["constant_registers"] == {"rax": 5}
    assert payload["reaching_definition"] == {}
    assert payload["warnings"] == []
    assert payload["evidence"]["source"] == "dataflow.def_use"
    assert payload["evidence"]["method"] == "forward_propagation"
    assert payload["evidence"]["confidence"] == "medium"
    # Every other tool returns JSON-safe values; so must this one.
    assert json.loads(json.dumps(payload)) == payload


def test_dataflow_rejects_bad_addresses_and_zero_budgets(const_elf_path: Path) -> None:
    with pytest.raises(AnalysisError, match="address must be non-negative"):
        tools.dataflow(str(const_elf_path), -1)
    with pytest.raises(AnalysisError, match="not inside an executable section"):
        tools.dataflow(str(const_elf_path), 0x700000)
    with pytest.raises(AnalysisError, match="max_instructions must be between 1 and"):
        tools.dataflow(str(const_elf_path), TEXT_ADDRESS, max_instructions=0)
    with pytest.raises(AnalysisError, match="max_blocks must be between 1 and"):
        tools.dataflow(str(const_elf_path), TEXT_ADDRESS, max_blocks=0)




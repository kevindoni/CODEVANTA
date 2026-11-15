"""dex lane tests: DEX header/index-tables parser.

Every fixture is assembled in this module -- a tiny but structurally valid
DEX is built byte by byte (header, six index tables, MUTF-8 string data
including a ``0xC0 0x80`` NUL case) with the Adler-32 checksum and SHA-1
signature computed exactly as the format requires -- so the tests stay
offline and self-contained. What is asserted is the decoded fields, the
typed ``AnalysisError`` contract (bad magic, truncated header/table,
oversize and missing files), the checksum-mismatch warning, determinism of
``to_dict`` and the MCP tool wiring only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest

from codevanta.analysis.dex import MAX_FILE_BYTES, DexSummary, parse_dex
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

# --- 8< --- fixture: hand-built minimal DEX -----------------------------------


def _uleb128(value: int) -> bytes:
    """Encode one unsigned integer as uleb128 (the inverse of the parser)."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


#: "hi\N{NULL}é" -- exercises the 0xC0 0x80 NUL and a 2-byte sequence.
_STRING_WITH_NUL = "hi\x00é"
_MUTF8_WITH_NUL = b"hi\xC0\x80\xC3\xA9"

#: Layout of the hand-built DEX (offsets are also asserted via the parser).
_STRING_IDS_OFF = 112
_TYPE_IDS_OFF = 120
_PROTO_IDS_OFF = 124
_METHOD_IDS_OFF = 136
_CLASS_DEFS_OFF = 144
_DATA_OFF = 176


def _build_dex(version: str = "035") -> bytes:
    """Build a tiny valid DEX: 2 strings, 1 type, 1 proto, 1 method, 1 class."""
    # string data items live after the tables
    s0 = _uleb128(len("Lcom/foo/Bar;")) + b"Lcom/foo/Bar;" + b"\x00"
    s1 = _uleb128(len(_STRING_WITH_NUL)) + _MUTF8_WITH_NUL + b"\x00"
    total = _DATA_OFF + len(s0) + len(s1)

    blob = bytearray(total)
    blob[0:8] = b"dex\n" + version.encode("ascii") + b"\x00"
    struct.pack_into(
        "<8sI20s20I",
        blob,
        0,
        b"dex\n" + version.encode("ascii") + b"\x00",
        0,  # checksum, patched below
        b"\x00" * 20,  # signature, patched below
        total,  # file_size
        112,  # header_size
        0x12345678,  # endian_tag
        0,
        0,  # link_size / link_off
        0,  # map_off
        2,
        _STRING_IDS_OFF,  # string_ids
        1,
        _TYPE_IDS_OFF,  # type_ids
        1,
        _PROTO_IDS_OFF,  # proto_ids
        0,
        0,  # field_ids (empty)
        1,
        _METHOD_IDS_OFF,  # method_ids
        1,
        _CLASS_DEFS_OFF,  # class_defs
        total - _DATA_OFF,
        _DATA_OFF,  # data_size / data_off
    )
    # string_ids: offsets of the two string_data_items
    struct.pack_into("<I", blob, _STRING_IDS_OFF, _DATA_OFF)
    struct.pack_into("<I", blob, _STRING_IDS_OFF + 4, _DATA_OFF + len(s0))
    # type_ids[0] -> descriptor string 0
    struct.pack_into("<I", blob, _TYPE_IDS_OFF, 0)
    # proto_ids[0]: shorty_idx=1, return_type_idx=0, parameters_off=0
    struct.pack_into("<3I", blob, _PROTO_IDS_OFF, 1, 0, 0)
    # method_ids[0]: class_idx=0, proto_idx=0, name_idx=1
    struct.pack_into("<HHI", blob, _METHOD_IDS_OFF, 0, 0, 1)
    # class_defs[0]: class_idx=0, access=0x1, superclass=NO_INDEX, rest zero
    struct.pack_into(
        "<8I", blob, _CLASS_DEFS_OFF, 0, 0x1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0, 0
    )
    blob[_DATA_OFF : _DATA_OFF + len(s0)] = s0
    blob[_DATA_OFF + len(s0) : _DATA_OFF + len(s0) + len(s1)] = s1
    # signature = sha1 of everything past it; checksum = adler32 of the rest.
    struct.pack_into("<20s", blob, 12, hashlib.sha1(bytes(blob[32:])).digest())
    struct.pack_into("<I", blob, 8, zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF)
    return bytes(blob)


@pytest.fixture()
def dex_path(tmp_path: Path) -> Path:
    """The hand-built minimal DEX written to disk once per test."""
    path = tmp_path / "classes.dex"
    path.write_bytes(_build_dex())
    return path


def _payload(result: object) -> dict:
    """Pull the JSON payload out of one MCP ``call_tool`` result."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")


# --- 8< --- parse: decoded fields -----------------------------------------------


def test_parses_handbuilt_minimal_dex() -> None:
    """The hand-built DEX decodes to the exact counts, samples and digests."""
    blob = _build_dex()
    summary = parse_dex(blob, source="fixture.dex")
    assert isinstance(summary, DexSummary)
    assert summary.path == "fixture.dex"
    assert summary.version == "035"
    assert summary.adler32_ok is True
    assert summary.sha1 == hashlib.sha1(blob[32:]).hexdigest()
    assert summary.declared_file_size == summary.actual_file_size == len(blob)
    assert summary.endian_tag == 0x12345678
    assert summary.string_count == 2
    assert summary.type_count == 1
    assert summary.proto_count == 1
    assert summary.field_count == 0
    assert summary.method_count == 1
    assert summary.class_count == 1
    assert summary.strings == ("Lcom/foo/Bar;", _STRING_WITH_NUL)
    assert summary.strings_truncated is False
    assert summary.classes == ("Lcom/foo/Bar;",)
    assert summary.classes_truncated is False
    assert summary.methods == (f"Lcom/foo/Bar;->{_STRING_WITH_NUL}",)
    assert summary.methods_truncated is False
    assert summary.warnings == ()
    assert summary.evidence.source == "dex.header"
    assert summary.evidence.confidence.value == "high"


def test_to_dict_is_json_safe_and_deterministic() -> None:
    """Two ``to_dict`` calls are identical and the payload JSON-encodes."""
    summary = parse_dex(_build_dex())
    first = summary.to_dict()
    second = summary.to_dict()
    assert first == second
    assert json.dumps(first) == json.dumps(second)
    assert first["counts"] == {
        "strings": 2,
        "types": 1,
        "protos": 1,
        "fields": 0,
        "methods": 1,
        "classes": 1,
    }
    assert first["evidence"]["source"] == "dex.header"


def test_decodes_all_supported_versions() -> None:
    """Versions 035/037/038/039 all parse with the version echoed back."""
    for version in ("035", "037", "038", "039"):
        summary = parse_dex(_build_dex(version))
        assert summary.version == version
        assert summary.adler32_ok is True


# --- 8< --- typed errors ---------------------------------------------------------


def test_bad_magic_is_typed_error() -> None:
    """A non-DEX file raises the typed 'not a DEX file' error."""
    with pytest.raises(AnalysisError, match="not a DEX file"):
        parse_dex(b"MZ\x90\x00" + b"\x00" * 200)


def test_unsupported_version_is_typed_error() -> None:
    """A well-formed magic with an unknown version is a typed error."""
    with pytest.raises(AnalysisError, match="unsupported DEX version"):
        parse_dex(_build_dex("030"))


def test_truncated_header_is_typed_error() -> None:
    """Fewer bytes than the fixed header is the typed truncated error."""
    with pytest.raises(AnalysisError, match="truncated DEX header"):
        parse_dex(_build_dex()[:80])


def test_truncated_table_is_typed_error() -> None:
    """A string_ids table whose extent leaves the file is a typed error."""
    with pytest.raises(AnalysisError, match="truncated DEX string_ids"):
        parse_dex(_build_dex()[:113])  # 112 header bytes + 1 of 8 table bytes


def test_checksum_mismatch_warns_but_parses() -> None:
    """A corrupted checksum is a warning; the parse still succeeds."""
    blob = bytearray(_build_dex())
    struct.pack_into("<I", blob, 8, 0xDEADBEEF)
    summary = parse_dex(bytes(blob))
    assert summary.adler32_ok is False
    assert any("checksum mismatch" in warning for warning in summary.warnings)
    assert summary.string_count == 2
    assert summary.classes == ("Lcom/foo/Bar;",)


# --- 8< --- MCP tool wiring -------------------------------------------------------


def test_tool_reads_file_and_returns_payload(dex_path: Path) -> None:
    """``tools.codevanta_dex`` reads the file once and returns the summary."""
    payload = tools.codevanta_dex(str(dex_path))
    assert payload["version"] == "035"
    assert payload["adler32_ok"] is True
    assert payload["counts"]["classes"] == 1
    assert payload["strings"] == ["Lcom/foo/Bar;", _STRING_WITH_NUL]


def test_missing_file_is_typed_error(tmp_path: Path) -> None:
    """A missing path is the typed 'file not found' error."""
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_dex(str(tmp_path / "absent.dex"))


def test_oversize_file_is_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file over the 64 MiB budget is refused with a typed error."""
    monkeypatch.setattr("codevanta.analysis.dex.MAX_FILE_BYTES", 8)
    path = tmp_path / "big.dex"
    path.write_bytes(b"dex\n035\x00" + b"\x00")  # 9 bytes > the patched budget
    with pytest.raises(AnalysisError, match="file too large"):
        tools.codevanta_dex(str(path))


def test_server_registers_and_serves_dex_tool(dex_path: Path) -> None:
    """The MCP server registers ``codevanta_dex`` and serves its payload."""
    listed = asyncio.run(build_server().list_tools())
    assert "codevanta_dex" in {tool.name for tool in listed}
    result = asyncio.run(build_server().call_tool("codevanta_dex", {"path": str(dex_path)}))
    payload = _payload(result)
    assert payload["version"] == "035"
    assert payload["adler32_ok"] is True
    assert payload["counts"]["strings"] == 2


def test_server_maps_typed_errors_to_tool_error(tmp_path: Path) -> None:
    """An AnalysisError from the tool surfaces as the typed ToolError."""
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="file not found"):
        asyncio.run(
            build_server().call_tool("codevanta_dex", {"path": str(tmp_path / "gone.dex")})
        )


def test_default_budget_is_64_mib() -> None:
    """The shipped byte budget stays at 64 MiB."""
    assert MAX_FILE_BYTES == 64 * 1024 * 1024

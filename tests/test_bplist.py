"""bplist lane tests: Apple binary property list (bplist00) decoder.

Every fixture is assembled in this module -- a hand-rolled ``_BplistWriter``
that lays down the marker-typed object table, the big-endian offset table and
the 32-byte trailer byte by byte -- so the tests stay offline and
self-contained. What is asserted is the decoded value tree, the typed
``AnalysisError`` for bad magic, truncated trailers, out-of-range object
references and self-referencing cycles, the bounded-work guards (string and
data caps) and the MCP tool wiring only.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from codevanta.analysis.bplist import MAX_STRING_CHARS, decode_bplist
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

# --- 8< --- helpers: hand-rolled bplist00 assembler (fixtures only) ----------


class _BplistWriter:
    """Hand-rolled bplist00 assembler mirroring the reader's grammar."""

    def __init__(self) -> None:
        self._objects: list[bytes] = []

    def _add(self, blob: bytes) -> int:
        self._objects.append(blob)
        return len(self._objects) - 1

    @staticmethod
    def _int_blob(value: int) -> bytes:
        if 0 <= value < 1 << 8:
            size = 1
        elif value < 1 << 16:
            size = 2
        elif value < 1 << 32:
            size = 4
        else:
            size = 8
        return bytes([0x10 | (size.bit_length() - 1)]) + value.to_bytes(
            size, "big", signed=value < 0
        )

    @staticmethod
    def _count_prefix(nibble: int, count: int) -> bytes:
        if count < 0xF:
            return bytes([(nibble << 4) | count])
        return bytes([(nibble << 4) | 0xF]) + _BplistWriter._int_blob(count)

    def add_ascii(self, text: str) -> int:
        raw = text.encode("latin-1")
        return self._add(self._count_prefix(0x5, len(raw)) + raw)

    def add_utf16(self, text: str) -> int:
        raw = text.encode("utf-16-be")
        return self._add(self._count_prefix(0x6, len(raw) // 2) + raw)

    def add_data(self, blob: bytes) -> int:
        return self._add(self._count_prefix(0x4, len(blob)) + blob)

    def add_int(self, value: int) -> int:
        return self._add(self._int_blob(value))

    def add_real(self, value: float) -> int:
        return self._add(bytes([0x23]) + struct.pack(">d", value))

    def add_date(self, seconds: float) -> int:
        return self._add(bytes([0x33]) + struct.pack(">d", seconds))

    def add_bool(self, flag: bool) -> int:
        return self._add(bytes([0x09 if flag else 0x08]))

    def _refs_blob(self, refs: list[int], ref_size: int) -> bytes:
        return b"".join(ref.to_bytes(ref_size, "big") for ref in refs)

    def add_array(
        self, refs: list[int], ref_size: int = 2, *, set_marker: bool = False
    ) -> int:
        nibble = 0xB if set_marker else 0xA
        return self._add(
            self._count_prefix(nibble, len(refs)) + self._refs_blob(refs, ref_size)
        )

    def add_dict(
        self, keys: list[int], values: list[int], ref_size: int = 2
    ) -> int:
        assert len(keys) == len(values)
        return self._add(
            self._count_prefix(0xD, len(keys))
            + self._refs_blob(keys, ref_size)
            + self._refs_blob(values, ref_size)
        )

    def build(
        self,
        top: int,
        *,
        offset_int_size: int = 4,
        object_ref_size: int = 2,
        magic: bytes = b"bplist00",
    ) -> bytes:
        body = bytearray(magic)
        offsets: list[int] = []
        for obj in self._objects:
            offsets.append(len(body))
            body += obj
        offset_table_offset = len(body)
        for offset in offsets:
            body += offset.to_bytes(offset_int_size, "big")
        body += b"\x00" * 6
        body += bytes([offset_int_size, object_ref_size])
        body += len(self._objects).to_bytes(8, "big")
        body += top.to_bytes(8, "big")
        body += offset_table_offset.to_bytes(8, "big")
        return bytes(body)

# --- 8< --- fixture: dict with string/int/bool/array + a nested dict ---------


def _fixture_blob() -> bytes:
    """Build the canonical fixture: 21 objects, top object 20 (a dict)."""
    writer = _BplistWriter()
    name_key = writer.add_ascii("name")  # 0
    name_val = writer.add_ascii("bplist-fixture")  # 1
    count = writer.add_int(42)  # 2
    flag = writer.add_bool(True)  # 3
    alpha = writer.add_ascii("alpha")  # 4
    beta = writer.add_utf16("béta")  # 5
    items = writer.add_array([alpha, beta])  # 6
    deep_key = writer.add_ascii("deep")  # 7
    deep_val = writer.add_ascii("value")  # 8
    ratio_key = writer.add_ascii("ratio")  # 9
    ratio_val = writer.add_real(3.5)  # 10
    blob_key = writer.add_ascii("blob")  # 11
    blob_val = writer.add_data(b"\x00\x01\xfe\xff")  # 12
    stamp_key = writer.add_ascii("stamp")  # 13
    stamp_val = writer.add_date(0.0)  # 14
    nested = writer.add_dict(
        [deep_key, ratio_key, blob_key, stamp_key],
        [deep_val, ratio_val, blob_val, stamp_val],
    )  # 15
    items_key = writer.add_ascii("items")  # 16
    count_key = writer.add_ascii("count")  # 17
    flag_key = writer.add_ascii("flag")  # 18
    nested_key = writer.add_ascii("nested")  # 19
    top = writer.add_dict(
        [name_key, count_key, flag_key, items_key, nested_key],
        [name_val, count, flag, items, nested],
    )  # 20
    return writer.build(top)


# --- 8< --- decode: value tree -------------------------------------------------


def test_decode_round_trips_hand_built_fixture() -> None:
    """The hand-built fixture decodes to the exact expected bounded tree."""
    summary = decode_bplist(_fixture_blob())
    assert summary.version == "00"
    assert summary.num_objects == 21
    top = summary.top
    assert top["kind"] == "dict"
    assert top["length"] == 5
    assert top["truncated"] is False
    entries = {entry["key"]: entry["value"] for entry in top["entries"]}
    assert entries["name"] == {
        "kind": "string",
        "encoding": "ascii",
        "value": "bplist-fixture",
        "char_length": 14,
        "truncated": False,
    }
    assert entries["count"] == {"kind": "int", "value": 42, "byte_length": 1}
    assert entries["flag"] == {"kind": "bool", "value": True}
    array = entries["items"]
    assert array["kind"] == "array"
    assert array["length"] == 2
    assert array["items"][0]["value"] == "alpha"
    assert array["items"][1]["value"] == "béta"
    assert array["items"][1]["encoding"] == "utf16"
    nested = entries["nested"]
    nested_entries = {entry["key"]: entry["value"] for entry in nested["entries"]}
    assert nested_entries["deep"]["value"] == "value"
    assert nested_entries["ratio"] == {"kind": "real", "value": 3.5}
    assert nested_entries["blob"]["hex"] == "0001feff"
    assert nested_entries["blob"]["truncated"] is False
    assert nested_entries["stamp"]["value"] == "2001-01-01T00:00:00+00:00"
    assert summary.warnings == ()
    assert summary.evidence.source == "bplist.decode"
    assert summary.evidence.confidence.value == "high"

def test_decode_is_deterministic() -> None:
    """Two decodes of the same bytes produce identical dictionaries."""
    first = decode_bplist(_fixture_blob()).to_dict()
    second = decode_bplist(_fixture_blob()).to_dict()
    assert first == second


def test_bounds_clip_strings_and_preview_data() -> None:
    """Strings past the char cap are clipped; oversize data is a hex preview."""
    writer = _BplistWriter()
    text_ref = writer.add_ascii("x" * 300)
    big_data = bytes(range(256)) * 280  # 71680 bytes > MAX_DATA_BYTES
    data_ref = writer.add_data(big_data)
    keys = [writer.add_ascii("t"), writer.add_ascii("d")]
    top = writer.add_dict(keys, [text_ref, data_ref])
    summary = decode_bplist(writer.build(top))
    entries = {entry["key"]: entry["value"] for entry in summary.top["entries"]}
    clipped = entries["t"]
    assert clipped["truncated"] is True
    assert clipped["char_length"] == 300
    assert len(clipped["value"]) == MAX_STRING_CHARS
    blob = entries["d"]
    assert blob["byte_length"] == len(big_data)
    assert blob["truncated"] is True
    assert len(blob["hex"]) == 128  # MAX_DATA_PREVIEW_BYTES as hex digits
    assert any("clipped" in warning for warning in summary.warnings)
    assert any("hex preview only" in warning for warning in summary.warnings)


# --- 8< --- typed errors -------------------------------------------------------


def test_cycle_detected_as_typed_error() -> None:
    """A self-referencing dict (value ref points at its own index) raises."""
    writer = _BplistWriter()
    key = writer.add_ascii("self")  # object 0
    top = writer.add_dict([key], [1])  # object 1: the dict references itself
    with pytest.raises(AnalysisError, match="cycle detected"):
        decode_bplist(writer.build(top))


def test_out_of_range_top_object_is_typed_error() -> None:
    """A top object index past the declared table size is an object range error."""
    writer = _BplistWriter()
    writer.add_ascii("only")
    blob = writer.build(5)  # only 1 object exists
    with pytest.raises(AnalysisError, match="object range error"):
        decode_bplist(blob)


def test_bad_magic_is_typed_error() -> None:
    """Anything that is not bplist00 is refused with the bad-magic message."""
    blob = _fixture_blob().replace(b"bplist00", b"bplist0X", 1)
    with pytest.raises(AnalysisError, match="bad magic"):
        decode_bplist(blob)
    with pytest.raises(AnalysisError, match="bad magic"):
        decode_bplist(b"not a plist")


def test_truncated_trailer_is_typed_error() -> None:
    """A file too short to carry the 32-byte trailer is refused."""
    with pytest.raises(AnalysisError, match="truncated trailer"):
        decode_bplist(b"bplist00" + b"\x00" * 10)


# --- 8< --- MCP tool layer (`codevanta_bplist`) ---------------------------------


def test_mcp_bplist_tool_and_errors(tmp_path) -> None:
    """The tool layer decodes fixture files and rejects missing paths."""
    target = tmp_path / "fixture.plist"
    target.write_bytes(_fixture_blob())
    payload = tools.codevanta_bplist(str(target))
    assert payload["version"] == "00"
    assert payload["num_objects"] == 21
    assert payload["top"]["kind"] == "dict"
    assert payload["evidence"]["source"] == "bplist.decode"
    assert payload["evidence"]["confidence"] == "high"
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_bplist(str(tmp_path / "missing.plist"))


def test_server_registers_bplist_tool() -> None:
    """The lane tool is registered on the built MCP server."""
    listed = asyncio.run(build_server().list_tools())
    assert "codevanta_bplist" in {tool.name for tool in listed}

# --- 8< --- continued in the next chunk --------------------------------------

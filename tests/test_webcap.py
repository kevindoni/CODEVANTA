"""Web capture depth lane tests: HAR summaries + protobuf wire decode.

Everything here is offline and synthetic: the HAR fixtures are hand-built
JSON documents, the protobuf messages are hand-encoded byte strings decoded
back field by field, and the CLI runs through the in-process typer runner.
No network, no browser, no execution.
"""

from __future__ import annotations

import base64
import json
import struct
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.har_capture import (
    MAX_CONTENT_TYPES,
    MAX_ENTRIES,
    MAX_HOSTS,
    MAX_ROWS,
    load_har,
    looks_like_grpc_frame,
    summarise_har,
)
from codevanta.analysis.proto_wire import (
    MAX_DEPTH,
    MAX_FIELDS,
    MAX_HEX_CHARS,
    WIRE_I32,
    WIRE_I64,
    WIRE_LEN,
    WIRE_SGROUP,
    WIRE_VARINT,
    decode_message,
    load_proto_bytes,
    strip_grpc_frame,
)
from codevanta.cli.main import app as cli_app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools as mcp_tools

runner = CliRunner()


# ---- hand-encoding helpers -------------------------------------------------


def _varint(value: int) -> bytes:
    """Encode one base-128 varint (the protobuf way)."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field_number: int, wire_type: int) -> bytes:
    """Encode one field tag (field number << 3 | wire type)."""
    return _varint((field_number << 3) | wire_type)


def _len_field(field_number: int, payload: bytes) -> bytes:
    """Encode one length-delimited field."""
    return _tag(field_number, WIRE_LEN) + _varint(len(payload)) + payload


def _grpc_frame(payload: bytes, *, flag: int = 0) -> bytes:
    """Wrap ``payload`` in the 5-byte gRPC frame prefix."""
    return bytes([flag]) + len(payload).to_bytes(4, "big") + payload


# ---- HAR fixture builders ---------------------------------------------------


def _har_entry(
    method: str,
    url: str,
    status: int,
    mime: str,
    *,
    time_ms: float = 1.0,
    started: str = "2024-01-01T00:00:00Z",
    body: bytes | None = None,
    encoding: str | None = None,
    use_headers_mime: bool = False,
) -> dict[str, Any]:
    """Build one HAR entry dict (request/response/content)."""
    response: dict[str, Any] = {"status": status, "headers": []}
    if use_headers_mime:
        response["headers"] = [{"name": "Content-Type", "value": mime}]
    else:
        response["content"] = {"mimeType": mime}
    if body is not None:
        content = response.setdefault("content", {})
        if encoding == "base64":
            content["encoding"] = "base64"
            content["text"] = base64.b64encode(body).decode("ascii")
        else:
            content["text"] = body.decode("utf-8", errors="replace")
    return {
        "startedDateTime": started,
        "time": time_ms,
        "request": {"method": method, "url": url},
        "response": response,
    }


def _write_har(path: Path, entries: list[dict[str, Any]]) -> Path:
    """Write a synthetic HAR document and return its path."""
    document = {"log": {"creator": {"name": "t", "version": "1"}, "entries": entries}}
    path.write_bytes(json.dumps(document).encode("utf-8"))
    return path
# ---- HAR tests ----------------------------------------------------------------


def test_har_summary_three_entries_with_grpc_and_image(tmp_path: Path) -> None:
    grpc_payload = bytes([0x08, 0x05])  # tiny protobuf: varint field 1 = 5
    entries = [
        _har_entry(
            "GET",
            "https://api.example.com/index.html",
            200,
            "text/html; charset=utf-8",
            time_ms=12.5,
            started="2024-01-01T00:00:00Z",
        ),
        _har_entry(
            "POST",
            "https://grpc.example.com/pkg.Service/Get",
            200,
            "application/grpc",
            time_ms=3.25,
            started="2024-01-01T00:00:01Z",
            body=_grpc_frame(grpc_payload),
            encoding="base64",
        ),
        _har_entry(
            "GET",
            "https://cdn.example.com/img/logo.png",
            200,
            "image/png",
            time_ms=1.0,
            started="2024-01-01T00:00:02Z",
            body=b"\x89PNG\r\n\x1a\nrest",
        ),
    ]
    summary = summarise_har(json.dumps({"log": {"entries": entries}}).encode())
    assert summary.entry_count == 3
    assert summary.total_time_ms == 16.75
    assert summary.started_first == "2024-01-01T00:00:00Z"
    assert summary.started_last == "2024-01-01T00:00:02Z"
    assert summary.content_types == {
        "text/html": 1,
        "application/grpc": 1,
        "image/png": 1,
    }
    assert summary.hosts == ("api.example.com", "grpc.example.com", "cdn.example.com")
    assert summary.grpc_count == 1
    assert summary.truncated is False
    html, grpc, image = summary.rows
    assert (html.method, html.status) == ("GET", 200)
    assert html.grpc is False and html.grpc_length is None
    assert grpc.grpc is True
    assert grpc.grpc_length == len(grpc_payload)
    assert image.grpc is False and image.content_type == "image/png"
    assert summary.evidence.source == "web.har"
    assert summary.evidence.method == "har_entry_walk"
    assert summary.evidence.confidence.value == "certain"
    payload = summary.to_dict()
    assert json.loads(json.dumps(payload)) == payload


def test_load_har_reads_the_file(tmp_path: Path) -> None:
    path = _write_har(
        tmp_path / "capture.har",
        [_har_entry("GET", "https://one.example.com/", 200, "text/html")],
    )
    summary = load_har(path)
    assert summary.entry_count == 1
    assert summary.hosts == ("one.example.com",)


def test_har_grpc_detected_by_frame_prefix_without_content_type() -> None:
    payload = b"\x01"  # ASCII-safe: survives the raw-text JSON round trip
    entry = _har_entry(
        "POST",
        "https://svc.example.com/Call",
        200,
        "text/plain",
        body=_grpc_frame(payload, flag=1),
    )
    summary = summarise_har(json.dumps({"log": {"entries": [entry]}}).encode())
    row = summary.rows[0]
    assert row.grpc is True
    assert row.grpc_length == len(payload)
    # Binary frames survive only as base64 (real-world HAR encoding).
    binary = _har_entry(
        "POST",
        "https://svc.example.com/Call",
        200,
        "text/plain",
        body=_grpc_frame(_varint(300), flag=1),
        encoding="base64",
    )
    decoded = summarise_har(json.dumps({"log": {"entries": [binary]}}).encode())
    assert decoded.rows[0].grpc is True
    assert decoded.rows[0].grpc_length == 2


def test_har_content_type_falls_back_to_response_headers() -> None:
    entry = _har_entry(
        "POST",
        "https://svc.example.com/Call",
        200,
        "application/grpc",
        use_headers_mime=True,
    )
    summary = summarise_har(json.dumps({"log": {"entries": [entry]}}).encode())
    assert summary.rows[0].content_type == "application/grpc"
    assert summary.grpc_count == 1


def test_har_rejects_non_har_json(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        summarise_har(b"<html>not json</html>")
    with pytest.raises(AnalysisError):
        summarise_har(b'["a", "list"]')
    with pytest.raises(AnalysisError):
        summarise_har(b'{"other": {}}')
    with pytest.raises(AnalysisError):
        summarise_har(b'{"log": 42}')
    with pytest.raises(AnalysisError):
        summarise_har(b'{"log": {"entries": {}}}')
    with pytest.raises(AnalysisError):
        load_har(tmp_path / "missing.har")
    with pytest.raises(AnalysisError):
        load_har(tmp_path)


def test_har_bounds_entries_rows_hosts_and_types(tmp_path: Path) -> None:
    entries = [
        _har_entry(
            "GET",
            f"https://host{index}.example.com/path",
            200,
            f"type/{index}",
        )
        for index in range(MAX_ENTRIES + 10)
    ]
    summary = summarise_har(json.dumps({"log": {"entries": entries}}).encode())
    assert summary.entry_count == MAX_ENTRIES
    assert len(summary.rows) == MAX_ROWS
    assert len(summary.content_types) == MAX_CONTENT_TYPES
    assert len(summary.hosts) == MAX_HOSTS
    assert summary.truncated is True

# ---- protobuf wire tests ------------------------------------------------------


def test_hand_encoded_message_decodes_back_exactly() -> None:
    nested = _tag(1, WIRE_VARINT) + _varint(5)
    encoded = (
        _tag(1, WIRE_VARINT)
        + _varint(300)                       # varint field 1 = 300
        + _tag(2, WIRE_I64)
        + struct.pack("<d", 3.14)            # fixed64 field 2 = 3.14
        + _len_field(3, nested)              # message field 3 (nested varint 5)
        + _tag(5, WIRE_I32)
        + struct.pack("<f", 2.5)             # fixed32 field 5 = 2.5
    )
    result = decode_message(encoded)
    assert len(result.fields) == 4
    first, second, third, fourth = result.fields
    assert (first.field_number, first.kind, first.value) == (1, "varint", 300)
    assert (second.field_number, second.kind, second.value) == (2, "fixed64", 3.14)
    assert third.kind == "message"
    (inner,) = third.value
    assert inner.field_number == 1
    assert inner.value == 5
    assert inner.depth == 1
    assert (fourth.field_number, fourth.kind, fourth.value) == (5, "fixed32", 2.5)
    assert result.field_count == 5
    assert result.depth_reached == 1
    assert result.warnings == ()
    assert result.evidence is not None
    assert result.evidence.confidence.value == "medium"
    payload = result.to_dict()
    assert json.loads(json.dumps(payload)) == payload


def test_varint_edge_values_decode_exactly() -> None:
    encoded = (
        _tag(1, WIRE_VARINT)
        + _varint(0)
        + _tag(2, WIRE_VARINT)
        + _varint(1)
        + _tag(3, WIRE_VARINT)
        + _varint(2**63)
        + _tag(4, WIRE_VARINT)
        + _varint(2**64 - 1)  # ten bytes, the largest legal varint
    )
    result = decode_message(encoded)
    assert [field.value for field in result.fields] == [0, 1, 2**63, 2**64 - 1]
    assert result.warnings == ()


def test_len_payload_that_is_not_a_message_reports_bounded_hex() -> None:
    raw = bytes(range(256))
    result = decode_message(_len_field(7, raw))
    (field,) = result.fields
    assert field.kind == "bytes"
    value = field.value
    assert isinstance(value, str)
    assert len(value) == MAX_HEX_CHARS + 1  # cut preview plus the ellipsis
    assert value.endswith("…")
    assert result.warnings == ()


def test_unknown_wire_type_becomes_a_warning_not_a_crash() -> None:
    result = decode_message(_tag(1, 6) + b"\x00")
    assert result.fields == ()
    assert result.field_count == 0
    assert any("unknown wire type 6" in warning for warning in result.warnings)
    wire7 = decode_message(_tag(1, 7))
    assert any("unknown wire type 7" in warning for warning in wire7.warnings)


def test_truncated_payloads_become_warnings() -> None:
    cases = [
        _tag(1, WIRE_VARINT) + b"\x80",            # varint never terminates
        _tag(2, WIRE_I64) + b"\x01\x02",           # 2 of 8 fixed64 bytes
        _tag(3, WIRE_I32) + b"\x01",               # 1 of 4 fixed32 bytes
        _tag(4, WIRE_LEN) + _varint(100) + b"ab",  # declared 100, got 2
        _tag(5, WIRE_SGROUP) + _tag(1, WIRE_VARINT) + _varint(1),  # no end-group
    ]
    for case in cases:
        result = decode_message(case)
        assert result.fields == ()
        assert result.warnings, f"expected a warning for {case!r}"
    # Partial fields survive a mid-message break.
    partial = decode_message(_tag(1, WIRE_VARINT) + _varint(9) + _tag(2, WIRE_I64))
    assert partial.fields[0].value == 9
    assert partial.warnings


def test_unmatched_end_group_warns() -> None:
    result = decode_message(_tag(1, 4))
    assert result.fields == ()
    assert any("end-group" in warning for warning in result.warnings)

def test_group_field_nests_until_its_end_group() -> None:
    inner = _tag(2, WIRE_VARINT) + _varint(42)
    encoded = _tag(1, WIRE_SGROUP) + inner + _tag(1, 4)
    result = decode_message(encoded)
    (group,) = result.fields
    assert group.kind == "group"
    (child,) = group.value
    assert child.field_number == 2
    assert child.value == 42
    assert child.depth == 1
    assert result.warnings == ()


def test_depth_is_bounded_and_deeper_payloads_become_bytes() -> None:
    payload = b"\x01\x02\x03"  # never parses as a message
    for _ in range(12):
        payload = _len_field(1, payload)
    result = decode_message(payload)
    assert result.depth_reached == MAX_DEPTH - 1
    assert any(f"max depth ({MAX_DEPTH})" in warning for warning in result.warnings)


def test_field_budget_bounds_the_walk() -> None:
    encoded = (_tag(9, WIRE_VARINT) + _varint(1)) * (MAX_FIELDS + 20)
    result = decode_message(encoded)
    assert result.field_count == MAX_FIELDS
    assert any(f"field budget ({MAX_FIELDS})" in warning for warning in result.warnings)


def test_empty_message_reports_zero_fields() -> None:
    result = decode_message(b"")
    assert result.fields == ()
    assert result.field_count == 0
    assert result.depth_reached == 0
    assert any("empty message" in warning for warning in result.warnings)


def test_decode_rejects_wrong_types_and_bounds() -> None:
    with pytest.raises(AnalysisError):
        decode_message("not bytes")  # type: ignore[arg-type]
    with pytest.raises(AnalysisError):
        decode_message(b"\x08\x01", max_depth=0)
    with pytest.raises(AnalysisError):
        decode_message(b"\x08\x01", max_fields=0)
    with pytest.raises(AnalysisError):
        decode_message(b"\x08\x01", max_depth=MAX_DEPTH + 1)
    # bytearray is accepted like bytes.
    assert decode_message(bytearray(b"\x08\x01")).fields[0].value == 1


# ---- gRPC frame tests ----------------------------------------------------------


def test_strip_grpc_frame_strips_only_valid_prefixes() -> None:
    payload = b"\x08\x01"
    frame = strip_grpc_frame(_grpc_frame(payload))
    assert frame.present is True
    assert frame.message_length == len(payload)
    assert frame.payload == payload
    assert frame.to_dict() == {
        "present": True,
        "payload_size": len(payload),
        "message_length": len(payload),
    }
    bare = strip_grpc_frame(payload)
    assert bare.present is False
    assert bare.message_length is None
    assert bare.payload == payload
    assert bare.to_dict() == {"present": False, "payload_size": len(payload)}
    assert looks_like_grpc_frame(b"\x02" + (0).to_bytes(4, "big")) is False
    assert looks_like_grpc_frame(_grpc_frame(payload)[:-1]) is False
    assert looks_like_grpc_frame(payload) is False


def test_decode_message_with_grpc_flag_strips_first() -> None:
    message = _tag(1, WIRE_VARINT) + _varint(7)
    result = decode_message(_grpc_frame(message), strip_grpc=True)
    assert result.grpc_frame is not None
    assert result.grpc_frame.present is True
    assert result.grpc_frame.message_length == len(message)
    assert result.fields[0].value == 7
    without = decode_message(_grpc_frame(message), strip_grpc=False)
    assert without.grpc_frame is None
    assert without.fields == ()
    assert without.warnings  # the frame prefix reads as an invalid tag

# ---- file loaders ---------------------------------------------------------------


def test_load_proto_bytes_reads_and_refuses(tmp_path: Path) -> None:
    body = tmp_path / "body.bin"
    body.write_bytes(_tag(1, WIRE_VARINT) + _varint(2))
    assert load_proto_bytes(body) == b"\x08\x02"
    with pytest.raises(AnalysisError):
        load_proto_bytes(tmp_path / "missing.bin")
    with pytest.raises(AnalysisError):
        load_proto_bytes(tmp_path)


# ---- CLI ------------------------------------------------------------------------


def _three_entry_har(tmp_path: Path) -> Path:
    grpc_payload = bytes([0x08, 0x05])
    return _write_har(
        tmp_path / "capture.har",
        [
            _har_entry("GET", "https://api.example.com/", 200, "text/html"),
            _har_entry(
                "POST",
                "https://grpc.example.com/Get",
                200,
                "application/grpc",
                body=_grpc_frame(grpc_payload),
                encoding="base64",
            ),
            _har_entry("GET", "https://cdn.example.com/logo.png", 200, "image/png"),
        ],
    )


def test_cli_web_capture_json(tmp_path: Path) -> None:
    har = _three_entry_har(tmp_path)
    result = runner.invoke(cli_app, ["web", "capture", str(har), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["entry_count"] == 3
    assert payload["grpc_count"] == 1
    assert payload["evidence"]["source"] == "web.har"


def test_cli_web_capture_table(tmp_path: Path) -> None:
    har = _three_entry_har(tmp_path)
    result = runner.invoke(cli_app, ["web", "capture", str(har)])
    assert result.exit_code == 0, result.output
    assert "entries: 3" in result.output
    assert "grpc: 1" in result.output
    assert "evidence: web.har/har_entry_walk" in result.output


def test_cli_web_capture_rejects_malformed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.har"
    bad.write_bytes(b"{not json")
    result = runner.invoke(cli_app, ["web", "capture", str(bad)])
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_web_proto_json_with_grpc(tmp_path: Path) -> None:
    message = _tag(1, WIRE_VARINT) + _varint(300)
    body = tmp_path / "body.bin"
    body.write_bytes(_grpc_frame(message))
    result = runner.invoke(cli_app, ["web", "proto", str(body), "--grpc", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["field_count"] == 1
    assert payload["grpc_frame"]["present"] is True
    assert payload["grpc_frame"]["message_length"] == len(message)
    assert payload["fields"][0]["value"] == 300


def test_cli_web_proto_table_and_warnings(tmp_path: Path) -> None:
    truncated = _tag(2, WIRE_I64) + b"\x01\x02"
    body = tmp_path / "broken.bin"
    body.write_bytes(truncated)
    result = runner.invoke(cli_app, ["web", "proto", str(body)])
    assert result.exit_code == 0, result.output
    assert "warning:" in result.output
    assert "fields: 0" in result.output
    assert "web.proto/wire_field_walk" in result.output


def test_cli_web_proto_rejects_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(
        cli_app, ["web", "proto", str(tmp_path / "nope.bin"), "--grpc"]
    )
    assert result.exit_code == 2
    assert "error:" in result.output

def test_server_registers_webcap_tools(tmp_path: Path) -> None:
    import asyncio

    from codevanta.mcp_server.server import build_server

    har = _three_entry_har(tmp_path)
    listed = asyncio.run(build_server().list_tools())
    names = {tool.name for tool in listed}
    assert {"codevanta_web_capture", "codevanta_proto_decode"} <= names
    result = asyncio.run(
        build_server().call_tool("codevanta_web_capture", {"path": str(har)})
    )
    payload = _result_payload(result)
    assert payload["entry_count"] == 3


def _result_payload(result: object) -> dict:
    """Extract the JSON payload from one MCP call_tool result."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")


def test_har_defensive_field_types_never_crash(tmp_path: Path) -> None:
    from codevanta.analysis.har_capture import MAX_BODY_B64_CHARS

    entries: list[Any] = [
        "junk-entry",  # not a dict
        {"no": "request"},  # request missing
        {  # odd field types everywhere
            "startedDateTime": 42,
            "time": "12",
            "request": {"method": 7, "url": "not-a-url"},
            "response": {
                "status": "200",
                "headers": {},
                "content": {"mimeType": "text/html", "text": ""},
            },
        },
        {  # bool and int times, header-junk fallback
            "time": True,
            "request": {"method": "GET", "url": "https://a.example.com/x"},
            "response": {"status": True, "headers": ["junk"]},
        },
        {  # int time, non-matching then matching headers
            "time": 5,
            "request": {"method": "GET", "url": "https://b.example.com/x"},
            "response": {
                "status": 1,
                "headers": [
                    {"name": "Accept", "value": "*/*"},
                    {"name": "content-type", "value": "application/grpc"},
                ],
            },
        },
        {  # headers that never name a content type
            "request": {"method": "GET", "url": "https://c.example.com/x"},
            "response": {
                "status": 2,
                "headers": [{"name": "Accept", "value": "*/*"}],
            },
        },
        {  # repeated content type (histogram increment) + broken base64
            "request": {"method": "GET", "url": "https://a.example.com/y"},
            "response": {
                "status": 3,
                "content": {
                    "mimeType": "text/html",
                    "encoding": "base64",
                    "text": "!!!not-base64!!!",
                },
            },
        },
    ]
    oversized = {
        "request": {"method": "GET", "url": "https://d.example.com/x"},
        "response": {
            "status": 4,
            "content": {
                "mimeType": "text/html",
                "encoding": "base64",
                "text": "A" * (MAX_BODY_B64_CHARS + 1),
            },
        },
    }
    summary = summarise_har(
        json.dumps({"log": {"entries": entries + [oversized]}}).encode()
    )
    assert summary.entry_count == 6  # junk entries are skipped, not counted
    assert summary.content_types == {"text/html": 3, "application/grpc": 1}
    assert summary.grpc_count == 1  # via the header fallback entry
    assert summary.truncated is True  # junk entries and the oversized probe
    assert summary.rows[2].status == 1
    assert summary.rows[2].time_ms == 5.0
    assert summary.rows[1].time_ms == 0.0  # bool time collapses to 0
    assert summary.rows[4].status == 3  # int status widened
    assert summary.rows[2].grpc is True  # header fallback entry
    assert summary.rows[5].content_type == "text/html"  # oversized probe still typed


def test_load_har_guards_oversize_and_read_failure(tmp_path: Path, monkeypatch) -> None:
    from codevanta.analysis import har_capture

    body = tmp_path / "body.html"
    body.write_bytes(b"not a har")
    monkeypatch.setattr(har_capture, "MAX_FILE_BYTES", 4)
    with pytest.raises(AnalysisError):
        load_har(body)
    monkeypatch.setattr(har_capture, "MAX_FILE_BYTES", har_capture.MAX_FILE_BYTES)

    def _explode(self: Path) -> bytes:
        raise OSError("disk went away")

    monkeypatch.setattr(Path, "read_bytes", _explode)
    with pytest.raises(AnalysisError):
        load_har(body)



# ---- MCP tools ------------------------------------------------------------------


def test_mcp_web_capture_returns_har_payload(tmp_path: Path) -> None:
    har = _three_entry_har(tmp_path)
    payload = mcp_tools.codevanta_web_capture(str(har))
    assert payload["entry_count"] == 3
    assert payload["evidence"]["confidence"] == "certain"
    assert json.loads(json.dumps(payload)) == payload


def test_mcp_proto_decode_strips_grpc(tmp_path: Path) -> None:
    message = _len_field(3, _tag(1, WIRE_VARINT) + _varint(5))
    body = tmp_path / "body.bin"
    body.write_bytes(_grpc_frame(message))
    payload = mcp_tools.codevanta_proto_decode(str(body), grpc=True)
    assert payload["grpc_frame"]["present"] is True
    assert payload["fields"][0]["kind"] == "message"
    assert json.loads(json.dumps(payload)) == payload


def test_mcp_proto_decode_rejects_bad_input(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_proto_decode(str(tmp_path / "missing.bin"))
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_web_capture(str(tmp_path / "missing.har"))
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_proto_decode(123)  # type: ignore[arg-type]


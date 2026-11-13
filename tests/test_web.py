"""Web/CDP + ASAR lane tests: all offline, no live browser required.

The CDP pieces run against a fake in-process DevTools server (a real TCP
socket in a thread), so the WebSocket handshake, frame codec and message
envelope are exercised end-to-end without any Electron installation. Dead
endpoints produce the typed ``CdpError`` / ``available: false`` outcomes the
lane promises.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import zlib
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.asar import (
    MAX_FILES,
    extract_file,
    list_archive,
    parse_header,
)
from codevanta.analysis.cdp_client import (
    OPCODE_TEXT,
    CdpError,
    capture_screenshot,
    decode_frame,
    encode_frame,
    encode_request,
    find_target,
    frame_needs_more,
    inspect_page,
    list_targets,
    mask_payload,
    parse_message,
    webmcp_get_tools,
)
from codevanta.cli.main import app as cli_app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools as mcp_tools

runner = CliRunner()


# ---- ASAR fixture builder (byte-by-byte pickle header + JSON tree) ----------


def _add_file(tree: dict[str, Any], name: str, attrs: dict[str, Any]) -> None:
    """Insert one file node into an ASAR header tree, creating directories."""
    parts = name.split("/")
    node = tree["files"]
    for part in parts[:-1]:
        child = node.setdefault(part, {"files": {}})
        node = child["files"]
    node[parts[-1]] = attrs


def _build_asar(
    tmp_path: Path,
    files: dict[str, bytes],
    *,
    name: str = "app.asar",
    unpacked: tuple[str, ...] = (),
    integrity: bool = False,
) -> tuple[Path, dict[str, int]]:
    """Write an .asar byte-by-byte and return it plus each entry's offset.

    The pickle header is ``UInt32LE(4)`` + ``UInt32LE(json_len)`` + the JSON
    tree padded with zeroes to a 4-byte boundary; the JSON length feeds back
    into the decimal-string offsets, so rendering repeats until stable.
    """
    path = tmp_path / name
    offsets: dict[str, int] = {}
    json_text = "{}"
    for _ in range(8):
        tree: dict[str, Any] = {"files": {}}
        cursor = 0
        for fname, content in files.items():
            attrs: dict[str, Any] = {}
            if fname not in unpacked:
                attrs["size"] = str(len(content))
                attrs["offset"] = str(cursor)
                offsets[fname] = cursor
                cursor += len(content)
            else:
                attrs["size"] = str(len(content))
                attrs["unpacked"] = True
            if integrity:
                attrs["integrity"] = {
                    "algorithm": "SHA256",
                    "hash": hashlib.sha256(content).hexdigest(),
                    "blockSize": 4_194_304,
                    "blocks": [],
                }
            _add_file(tree, fname, attrs)
        new_json = json.dumps(tree, separators=(",", ":"))
        if new_json == json_text:
            break
        json_text = new_json
    blob = (
        struct.pack("<II", 4, len(json_text))
        + json_text.encode("utf-8")
        + b"\x00" * (-len(json_text) % 4)
    )
    payload = b"".join(
        content for fname, content in files.items() if fname not in unpacked
    )
    path.write_bytes(blob + payload)
    return path, offsets


_MINIMAL_FILES = {
    "package.json": b'{"name": "demo", "main": "app/index.js"}\n',
    "app/index.js": b"console.log('hello from electron');\n",
    "app/assets/logo.png": b"\x89PNG\r\n\x1a\n-not-really",
}


def test_parse_header_offsets_and_base() -> None:
    """The pure parser decodes pickle sizes and the aligned data base."""
    json_text = '{"files": {"a.txt": {"size": "1", "offset": "0"}}}'
    data = (
        struct.pack("<II", 4, len(json_text))
        + json_text.encode()
        + b"\x00" * (-len(json_text) % 4)
        + b"x"
    )
    header = parse_header(data)
    assert header.json_length == len(json_text)
    assert header.base_offset == 8 + (-len(json_text) % 4) + len(json_text)
    assert header.evidence.source == "asar.parse"
    assert header.evidence.method == "pickle_header_walk"


def test_list_archive_counts_offsets_and_top_level_apps(tmp_path: Path) -> None:
    """Listing reports honest counts, byte offsets and the evidence chain."""
    archive, offsets = _build_asar(tmp_path, _MINIMAL_FILES)
    listing = list_archive(archive)
    assert listing.file_count == 3
    assert listing.dir_count == 2  # app/ and app/assets/
    assert listing.total_bytes == sum(len(blob) for blob in _MINIMAL_FILES.values())
    assert not listing.truncated
    assert listing.top_level_apps == ()  # package.json sits at the top level
    for entry in listing.files:
        assert entry.offset == offsets[entry.path]
        assert entry.size == len(_MINIMAL_FILES[entry.path])
    assert listing.evidence.source == "asar.parse"


def test_top_level_apps_detects_nested_package_json(tmp_path: Path) -> None:
    """A top-level directory holding package.json is reported as an app."""
    files = {
        "app/package.json": b'{"name": "nested"}',
        "app/main.js": b"// entry",
        "readme.md": b"# demo",
    }
    archive, _ = _build_asar(tmp_path, files)
    listing = list_archive(archive)
    assert listing.top_level_apps == ("app",)


def test_extract_round_trip(tmp_path: Path) -> None:
    """Extract returns the exact original bytes with a matching digest."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES, integrity=True)
    original = _MINIMAL_FILES["app/index.js"]
    result = extract_file(archive, "app/index.js")
    assert result.data == original
    assert result.sha256 == hashlib.sha256(original).hexdigest()
    assert result.evidence.source == "asar.parse"
    assert result.evidence.method == "range_read"
    assert result.to_dict()["size"] == len(original)


def test_extract_rejects_missing_directory_and_traversal(tmp_path: Path) -> None:
    """Typed errors for unknown entries, directories and path traversal."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES)
    with pytest.raises(AnalysisError):
        extract_file(archive, "app/missing.js")
    with pytest.raises(AnalysisError):
        extract_file(archive, "app")
    with pytest.raises(AnalysisError):
        extract_file(archive, "../../etc/passwd")


def test_unpacked_entry_refused(tmp_path: Path) -> None:
    """Entries flagged unpacked list fine but refuse byte extraction."""
    archive, _ = _build_asar(
        tmp_path, _MINIMAL_FILES, unpacked=("app/assets/logo.png",)
    )
    listing = list_archive(archive)
    flagged = [entry for entry in listing.files if entry.unpacked]
    assert [entry.path for entry in flagged] == ["app/assets/logo.png"]
    with pytest.raises(AnalysisError):
        extract_file(archive, "app/assets/logo.png")


def test_integrity_hash_surfaced(tmp_path: Path) -> None:
    """The header's whole-file SHA-256 lands on the entry record."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES, integrity=True)
    listing = list_archive(archive)
    for entry in listing.files:
        expected = hashlib.sha256(_MINIMAL_FILES[entry.path]).hexdigest()
        assert entry.integrity_hash == expected
        assert entry.to_dict()["integrity_sha256"] == expected


@pytest.mark.parametrize(
    "blob",
    [
        b"",  # empty
        b"PK\x03\x04not-an-asar-at-all",  # wrong magic: zip, not a pickle header
        b"\x10\x00\x00\x00" + b"\x00" * 12,  # first pickle size != 4
        struct.pack("<II", 4, 4_000_000) + b"{}",  # declared length over the cap
        struct.pack("<II", 4, 64) + b'{"files": {}}',  # truncated header
        struct.pack("<II", 4, 16) + b"not json at all!",  # non-JSON header
        struct.pack("<II", 4, 14) + b'{"files": []}\x00\x00',  # files not a map
    ],
)
def test_malformed_archives_raise_typed_errors(tmp_path: Path, blob: bytes) -> None:
    """Every malformed shape raises AnalysisError naming the defect."""
    archive = tmp_path / "broken.asar"
    archive.write_bytes(blob)
    with pytest.raises(AnalysisError):
        list_archive(archive)


def test_listing_bounded_at_512_files_with_honest_totals(tmp_path: Path) -> None:
    """More than 512 files truncates the listing, not the accounting."""
    files = {f"mod_{i:04d}.js": b"x" * (i % 7 + 1) for i in range(MAX_FILES + 100)}
    archive, _ = _build_asar(tmp_path, files)
    listing = list_archive(archive)
    assert listing.truncated
    assert len(listing.files) == MAX_FILES
    assert listing.file_count == len(files)
    assert listing.total_bytes == sum(len(blob) for blob in files.values())


# ---- WebSocket frame codec (pure + socketpair) ------------------------------


def test_decode_manual_masked_frame() -> None:
    """Hand-crafted client frame bytes parse back to the exact payload."""
    key = b"\x01\x02\x03\x04"
    payload = b"hello cdp"
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    raw = bytes([0x81, 0x80 | len(payload)]) + key + masked
    frame = decode_frame(raw)
    assert frame.fin
    assert frame.opcode == OPCODE_TEXT
    assert frame.payload == payload
    assert frame.consumed == len(raw)


def test_encode_decode_round_trip_pinned_key() -> None:
    """encode_frame with a pinned key is deterministic and round-trips."""
    payload = b"round-trip-payload"
    raw = encode_frame(OPCODE_TEXT, payload, mask_key=b"\xaa\x55\xaa\x55")
    assert raw[0] == 0x81
    assert raw[1] == 0x80 | len(payload)  # MASK bit + 7-bit length
    assert raw[2:6] == b"\xaa\x55\xaa\x55"
    assert raw[6:] == mask_payload(payload, b"\xaa\x55\xaa\x55")
    frame = decode_frame(raw)
    assert frame.payload == payload
    assert frame.fin
    assert frame.opcode == OPCODE_TEXT


@pytest.mark.parametrize("size", [0, 125, 126, 300, 70_000])
def test_extended_length_boundaries(size: int) -> None:
    """7-bit, 16-bit and 64-bit length encodings all round-trip."""
    payload = bytes(range(256)) * (size // 256) + bytes(size % 256)
    raw = encode_frame(OPCODE_TEXT, payload, mask_key=b"\x00\xff\x00\xff")
    frame = decode_frame(raw)
    assert frame.payload == payload
    assert frame.consumed == len(raw)


def test_oversize_frame_refused() -> None:
    """A declared payload over the 4 MiB cap is rejected before any copy."""
    over = 5 * 1024 * 1024
    raw = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", over) + b"\x00" * 4
    assert frame_needs_more(raw[:2])
    assert frame_needs_more(raw)  # 14 bytes present, 5 MiB declared
    with pytest.raises(CdpError):
        decode_frame(raw)


def test_truncated_frame_reported() -> None:
    """A frame that announces more bytes than it carries is incomplete."""
    payload = b"abc"
    key = b"\x0a\x0b\x0c\x0d"
    masked = mask_payload(payload, key)
    raw = bytes([0x81, 0x80 | len(payload)]) + key + masked
    assert frame_needs_more(raw[:-1])
    assert not frame_needs_more(raw)
    with pytest.raises(CdpError):
        decode_frame(raw[:-1])
    assert decode_frame(raw).payload == payload


def test_rsv_bits_refused() -> None:
    """Reserved RSV bits on the frame header are a protocol violation."""
    raw = bytes([0x81 | 0x40, 0x80]) + b"\x00" * 8
    with pytest.raises(CdpError):
        decode_frame(raw)


def test_frame_codec_over_socketpair() -> None:
    """Encoded client frames survive a real in-process socket hop."""
    left, right = socket.socketpair()
    with left, right:
        left.sendall(
            encode_frame(OPCODE_TEXT, b"pair-payload", mask_key=b"\x11\x22\x33\x44")
        )
        buffer = bytearray()
        while frame_needs_more(bytes(buffer)):
            chunk = right.recv(4096)
            assert chunk, "peer closed before a full frame arrived"
            buffer += chunk
        frame = decode_frame(bytes(buffer))
        assert frame.payload == b"pair-payload"
        assert frame.consumed == len(buffer)


# ---- CDP message envelope (pure) --------------------------------------------


def test_request_envelope_round_trip() -> None:
    """encode_request/parse_message round-trip a response envelope."""
    text = encode_request(3, "Page.getNavigationHistory", {"x": 1})
    message = parse_message(text)
    assert message.message_id == 3
    assert message.method is None
    assert not message.is_event
    assert message.result is None and message.error is None


def test_parse_event_and_error_shapes() -> None:
    """Events and error responses decode into the typed message record."""
    event = parse_message(
        '{"method": "Log.entryAdded", "params": {"entry": {"level": "error"}}}'
    )
    assert event.is_event
    assert event.method == "Log.entryAdded"
    assert event.params == {"entry": {"level": "error"}}
    error = parse_message('{"id": 9, "error": {"code": -32601, "message": "nope"}}')
    assert error.message_id == 9
    assert error.error is not None
    assert error.error["code"] == -32601


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"id": "nine"}',
        '{"id": 1, "result": 4}',
        '{"params": {}}',
    ],
)
def test_malformed_envelopes_raise_cdp_error(text: str) -> None:
    """Malformed CDP messages raise the typed error, never a silent None."""
    with pytest.raises(CdpError):
        parse_message(text)


# ---- fake in-process DevTools server (threading + real TCP) -----------------


def _server_frame(payload: bytes, *, fin: bool = True, opcode: int = 0x1) -> bytes:
    """Build an unmasked server-to-client WebSocket frame (RFC 6455)."""
    first = (0x80 if fin else 0) | opcode
    header = bytearray([first])
    size = len(payload)
    if size < 126:
        header.append(size)
    elif size <= 0xFFFF:
        header.append(126)
        header += struct.pack(">H", size)
    else:
        header.append(127)
        header += struct.pack(">Q", size)
    return bytes(header) + payload


def _png_1x1() -> bytes:
    """A minimal valid 1x1 grayscale PNG (signature + IHDR + IDAT + IEND)."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


_LOG_EVENT = {
    "method": "Log.entryAdded",
    "params": {
        "entry": {
            "level": "error",
            "text": "net::ERR_FAILED https://example.test/track.js",
            "source": "network",
        }
    },
}
_CONSOLE_EVENT = {
    "method": "Runtime.consoleAPICalled",
    "params": {
        "type": "warning",
        "args": [{"type": "string", "value": "deprecated API used"}],
    },
}
_FRAGMENTED_EVENT = json.dumps(
    {
        "method": "Runtime.consoleAPICalled",
        "params": {
            "type": "log",
            "args": [{"type": "string", "value": "fragmented message"}],
        },
    }
).encode("utf-8")


class _FakeDevtools:
    """A threaded stand-in for Chromium's DevTools endpoint on one TCP port.

    Answers ``GET /json`` with one page target, performs a real RFC 6455
    handshake, and replies to the lane's read-only queries. Console events
    (including one delivered as two fragments) are pushed after the enables,
    exactly the way a busy page emits them. ``webmcp="absent"`` makes the
    ``WebMCP.getAllTools`` probe fail with the standard unknown-domain error.
    """

    def __init__(self, *, webmcp: str = "absent") -> None:
        self.webmcp = webmcp
        self.methods_received: list[str] = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port: int = int(self._listener.getsockname()[1])
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=3)

    def _serve(self) -> None:
        self._listener.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self._handle(conn)
            except (OSError, CdpError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _read_head(self, conn: socket.socket) -> str:
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 65_536:
                break
        return bytes(buffer).decode("latin-1")

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        head = self._read_head(conn)
        first_line = head.split("\r\n", 1)[0]
        headers: dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if headers.get("upgrade", "").lower() == "websocket":
            self._handle_ws(conn, headers)
        elif first_line.startswith("GET /json"):
            body = json.dumps(
                [
                    {
                        "id": "PAGE1",
                        "type": "page",
                        "title": "CODEVANTA Test Page",
                        "url": "https://example.test/app",
                        "webSocketDebuggerUrl": (
                            f"ws://127.0.0.1:{self.port}/devtools/page/PAGE1"
                        ),
                    }
                ]
            ).encode("utf-8")
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
        else:
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")

    @staticmethod
    def _result(
        message_id: Any, result: dict[str, Any], *, error: dict[str, Any] | None = None
    ) -> bytes:
        payload: dict[str, Any] = {"id": message_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        return _server_frame(json.dumps(payload).encode())

    def _handle_ws(self, conn: socket.socket, headers: dict[str, str]) -> None:
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n"
        )
        buffer = bytearray()
        events_pushed = False
        while not self._stop.is_set():
            while frame_needs_more(bytes(buffer)):
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
            frame = decode_frame(bytes(buffer))
            del buffer[: frame.consumed]
            if frame.opcode == 0x8:  # close: echo and end
                conn.sendall(_server_frame(frame.payload, opcode=0x8))
                return
            if frame.opcode != 0x1:
                continue
            request = json.loads(frame.payload.decode("utf-8"))
            message_id = request.get("id")
            method = request.get("method", "")
            self.methods_received.append(method)
            replies: list[bytes] = []
            if method in ("Page.enable", "Log.enable", "Runtime.enable"):
                replies.append(self._result(message_id, {}))
                if not events_pushed and method == "Runtime.enable":
                    events_pushed = True
                    replies.append(_server_frame(json.dumps(_LOG_EVENT).encode()))
                    replies.append(_server_frame(json.dumps(_CONSOLE_EVENT).encode()))
                    # One event arrives as two fragments (fin=0, then opcode 0).
                    head, tail = _FRAGMENTED_EVENT[:40], _FRAGMENTED_EVENT[40:]
                    replies.append(_server_frame(head, fin=False))
                    replies.append(_server_frame(tail, opcode=0x0))
            elif method == "Page.getNavigationHistory":
                replies.append(
                    self._result(
                        message_id,
                        {
                            "index": 0,
                            "entries": [
                                {
                                    "url": "https://example.test/app",
                                    "title": "CODEVANTA Test Page",
                                }
                            ],
                        },
                    )
                )
            elif method == "Page.getResourceTree":
                replies.append(
                    self._result(
                        message_id,
                        {
                            "frameTree": {
                                "frame": {"url": "https://example.test/app"},
                                "resources": [
                                    {
                                        "url": "https://example.test/main.js",
                                        "type": "Script",
                                    },
                                    {
                                        "url": "https://example.test/app.css",
                                        "type": "Stylesheet",
                                    },
                                ],
                            }
                        },
                    )
                )
            elif method == "Page.captureScreenshot":
                replies.append(
                    self._result(
                        message_id,
                        {"data": base64.b64encode(_png_1x1()).decode()},
                    )
                )
            elif method == "WebMCP.getAllTools" and self.webmcp == "absent":
                replies.append(
                    self._result(
                        message_id,
                        {},
                        error={
                            "code": -32601,
                            "message": "'WebMCP.getAllTools' wasn't found",
                        },
                    )
                )
            elif method == "WebMCP.getAllTools":
                replies.append(
                    self._result(
                        message_id,
                        {
                            "tools": [
                                {"name": "codevanta_echo", "description": "echo a value"}
                            ]
                        },
                    )
                )
            else:
                replies.append(
                    self._result(
                        message_id,
                        {},
                        error={"code": -32601, "message": f"{method} wasn't found"},
                    )
                )
            for reply in replies:
                conn.sendall(reply)


@pytest.fixture
def fake_devtools():
    """A running fake endpoint, torn down after the test."""
    server = _FakeDevtools()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _dead_endpoint() -> str:
    """A loopback port that is guaranteed to refuse connections."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return f"http://127.0.0.1:{port}"


def test_list_targets_over_fake_server(fake_devtools: _FakeDevtools) -> None:
    """``/json`` targets decode into typed records with evidence."""
    targets = list_targets(fake_devtools.endpoint)
    assert targets.endpoint == fake_devtools.endpoint
    assert len(targets.targets) == 1
    target = targets.targets[0]
    assert target.target_id == "PAGE1"
    assert target.type == "page"
    assert target.title == "CODEVANTA Test Page"
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    assert target.ws_url == ws
    assert targets.to_dict()["count"] == 1
    assert targets.evidence.source == "cdp.inspect"
    with pytest.raises(CdpError):
        find_target(targets, "NOPE")


def test_inspect_page_is_passive_and_bounded(fake_devtools: _FakeDevtools) -> None:
    """Inspection reads identity/resources and overhears console traffic.

    The fake server records every method the client sent: the set must be
    exactly the five read-only queries, proving ``Runtime.evaluate`` (and
    every other mutating call) never leaves the lane.
    """
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    result = inspect_page(ws, observe_ms=200)
    assert result.title == "CODEVANTA Test Page"
    assert result.url == "https://example.test/app"
    assert [resource.type for resource in result.resources] == ["Script", "Stylesheet"]
    texts = [entry.text for entry in result.console]
    assert "net::ERR_FAILED https://example.test/track.js" in texts
    assert "deprecated API used" in texts
    assert "fragmented message" in texts  # assembled across continuation frames
    assert result.evidence.extra["evaluate_sent"] is False
    assert fake_devtools.methods_received == [
        "Page.enable",
        "Log.enable",
        "Runtime.enable",
        "Page.getNavigationHistory",
        "Page.getResourceTree",
    ]


def test_capture_screenshot_writes_bounded_png(
    fake_devtools: _FakeDevtools, tmp_path: Path
) -> None:
    """Screenshot bytes land on disk with parsed PNG dimensions."""
    out = tmp_path / "shot.png"
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    result = capture_screenshot(ws, out)
    assert out.read_bytes() == _png_1x1()
    assert result.byte_count == len(_png_1x1())
    assert (result.width, result.height) == (1, 1)
    assert result.evidence.source == "cdp.inspect"


def test_webmcp_absent_domain_is_typed_unavailable(
    fake_devtools: _FakeDevtools,
) -> None:
    """An unknown-domain reply becomes available=False, never an error."""
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    probe = webmcp_get_tools(ws)
    assert not probe.available
    assert probe.reason == "domain unavailable on this target"
    assert probe.tools == ()
    assert probe.evidence.source == "cdp.inspect"


def test_webmcp_present_domain_lists_tools() -> None:
    """A present WebMCP domain reports its bounded tool list."""
    server = _FakeDevtools(webmcp="present")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        probe = webmcp_get_tools(ws)
    finally:
        server.stop()
    assert probe.available
    assert probe.reason is None
    assert [tool.name for tool in probe.tools] == ["codevanta_echo"]


def test_dead_endpoint_raises_typed_cdp_error() -> None:
    """A closed port yields CdpError, an AnalysisError subclass."""
    dead = _dead_endpoint()
    with pytest.raises(CdpError) as excinfo:
        list_targets(dead)
    assert isinstance(excinfo.value, AnalysisError)
    with pytest.raises(AnalysisError):
        capture_screenshot("ws://127.0.0.1:1/devtools/page/X", Path("shot.png"))


def test_webmcp_dead_endpoint_stays_typed() -> None:
    """Even the probe degrades to available=False on a dead debugger."""
    probe = webmcp_get_tools("ws://127.0.0.1:1/devtools/page/X")
    assert not probe.available
    assert "unreachable" in (probe.reason or "")


# ---- MCP tool layer ---------------------------------------------------------


def test_mcp_web_inspect_skip_gated_on_dead_endpoint() -> None:
    """codevanta_web_inspect returns available=false instead of raising."""
    payload = mcp_tools.codevanta_web_inspect(_dead_endpoint())
    assert payload["available"] is False
    assert payload["evidence"]["source"] == "cdp.inspect"
    assert "reason" in payload


def test_mcp_web_inspect_happy_path(fake_devtools: _FakeDevtools) -> None:
    """With a live endpoint the MCP tool returns the inspection payload."""
    payload = mcp_tools.codevanta_web_inspect(fake_devtools.endpoint, observe_ms=200)
    assert payload["available"] is True
    assert payload["target_id"] == "PAGE1"
    assert payload["title"] == "CODEVANTA Test Page"
    assert payload["evidence"]["source"] == "cdp.inspect"


def test_mcp_asar_offline(tmp_path: Path) -> None:
    """codevanta_asar lists offline and reports one extracted entry."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES)
    payload = mcp_tools.codevanta_asar(str(archive))
    assert payload["file_count"] == 3
    assert payload["evidence"]["source"] == "asar.parse"
    extracted = mcp_tools.codevanta_asar(str(archive), extract="app/index.js")
    assert extracted["extract"]["size"] == len(_MINIMAL_FILES["app/index.js"])
    digest = hashlib.sha256(_MINIMAL_FILES["app/index.js"]).hexdigest()
    assert extracted["extract"]["sha256"] == digest


def test_mcp_asar_missing_file_raises_typed(tmp_path: Path) -> None:
    """A missing archive is a typed AnalysisError at the MCP layer."""
    with pytest.raises(AnalysisError):
        mcp_tools.codevanta_asar(str(tmp_path / "missing.asar"))


# ---- CLI --------------------------------------------------------------------


def test_cli_web_targets_dead_endpoint_exits_two() -> None:
    """A dead endpoint is a one-line typed error and exit code 2."""
    result = runner.invoke(cli_app, ["web", "targets", "--endpoint", _dead_endpoint()])
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_web_targets_and_inspect(fake_devtools: _FakeDevtools) -> None:
    """The web sub-app lists targets and inspects against the fake server."""
    listed = runner.invoke(
        cli_app, ["web", "targets", "--endpoint", fake_devtools.endpoint]
    )
    assert listed.exit_code == 0
    assert "PAGE1" in listed.output
    inspected = runner.invoke(
        cli_app,
        [
            "web",
            "inspect",
            "PAGE1",
            "--endpoint",
            fake_devtools.endpoint,
            "--observe-ms",
            "200",
            "--json",
        ],
    )
    assert inspected.exit_code == 0
    payload = json.loads(inspected.output)
    assert payload["title"] == "CODEVANTA Test Page"


def test_cli_web_webmcp_unavailable(fake_devtools: _FakeDevtools) -> None:
    """The webmcp command reports absence without failing."""
    result = runner.invoke(
        cli_app,
        ["web", "webmcp", "PAGE1", "--endpoint", fake_devtools.endpoint, "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["available"] is False


def test_cli_web_shot(fake_devtools: _FakeDevtools, tmp_path: Path) -> None:
    """The shot command writes the PNG to the requested path."""
    out = tmp_path / "cli-shot.png"
    result = runner.invoke(
        cli_app,
        ["web", "shot", "PAGE1", str(out), "--endpoint", fake_devtools.endpoint],
    )
    assert result.exit_code == 0
    assert out.read_bytes() == _png_1x1()


def test_cli_asar_listing_and_extract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``codevanta asar`` lists, emits JSON, and extracts to the CWD."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES)
    listing = runner.invoke(cli_app, ["asar", str(archive)])
    assert listing.exit_code == 0
    assert "app/index.js" in listing.output
    as_json = runner.invoke(cli_app, ["asar", str(archive), "--json"])
    assert as_json.exit_code == 0
    payload = json.loads(as_json.output)
    assert payload["file_count"] == 3
    monkeypatch.chdir(tmp_path)
    extracted = runner.invoke(
        cli_app, ["asar", str(archive), "--extract", "app/index.js", "--json"]
    )
    assert extracted.exit_code == 0, extracted.output
    written = tmp_path / "index.js"
    assert written.read_bytes() == _MINIMAL_FILES["app/index.js"]


def test_cli_asar_missing_archive_exits_two(tmp_path: Path) -> None:
    """A missing archive is a typed CLI error with exit code 2."""
    result = runner.invoke(cli_app, ["asar", str(tmp_path / "nope.asar")])
    assert result.exit_code == 2
    assert "error:" in result.output

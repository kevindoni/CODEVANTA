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
import time
import zlib
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis import cdp_client
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
    normalise_endpoint,
    parse_message,
    parse_ws_url,
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
_LATE_EVENT = {
    "method": "Runtime.consoleAPICalled",
    "params": {
        "type": "info",
        "args": [{"type": "string", "value": "late console traffic"}],
    },
}
_WEIRD_EVENTS = (
    {"method": "Log.entryAdded", "params": {"entry": 42}},
    {
        "method": "Runtime.consoleAPICalled",
        "params": {
            "type": "error",
            "args": [
                42,
                {"description": "desc only"},
                {"value": "str value"},
                {"value": {"k": 1}},
                {"value": None},
            ],
        },
    },
    {"method": "Page.frameNavigated", "params": {}},
)


class _FakeDevtools:
    """A threaded stand-in for Chromium's DevTools endpoint on one TCP port.

    Answers ``GET /json`` with one page target, performs a real RFC 6455
    handshake, and replies to the lane's read-only queries. Console events
    (including one delivered as two fragments) are pushed after the enables,
    exactly the way a busy page emits them. ``webmcp="absent"`` makes the
    ``WebMCP.getAllTools`` probe fail with the standard unknown-domain error.
    """

    def __init__(
        self,
        *,
        webmcp: str = "absent",
        nav: str | None = None,
        tree: str | None = None,
        events: str = "standard",
        late_event: bool = False,
        extra_targets: tuple[dict[str, Any], ...] = (),
        shot: str | None = None,
    ) -> None:
        self.webmcp = webmcp
        self.nav = nav
        self.tree = tree
        self.events = events
        self.late_event = late_event
        self.extra_targets = list(extra_targets)
        self.shot = shot
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

    def _push_late(self, conn: socket.socket) -> None:
        """Push one console event well after setup (exercise observe loop)."""
        if self._stop.is_set():
            return
        try:
            conn.sendall(_server_frame(json.dumps(_LATE_EVENT).encode()))
        except OSError:
            pass

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
            entries: list[dict[str, Any]] = [
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
            entries.extend(self.extra_targets)
            body = json.dumps(entries).encode("utf-8")
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
                    if self.events == "standard":
                        replies.append(_server_frame(json.dumps(_LOG_EVENT).encode()))
                        replies.append(
                            _server_frame(json.dumps(_CONSOLE_EVENT).encode())
                        )
                        # One event arrives as two fragments (fin=0, then opcode 0).
                        head, tail = _FRAGMENTED_EVENT[:40], _FRAGMENTED_EVENT[40:]
                        replies.append(_server_frame(head, fin=False))
                        replies.append(_server_frame(tail, opcode=0x0))
                    elif self.events == "weird":
                        for event in _WEIRD_EVENTS:
                            replies.append(_server_frame(json.dumps(event).encode()))
            elif method == "Page.getNavigationHistory":
                if self.nav == "weird":
                    payload: dict[str, Any] = {"index": 5, "entries": [42]}
                elif self.nav == "empty":
                    payload = {"index": 0, "entries": []}
                else:
                    payload = {
                        "index": 0,
                        "entries": [
                            {
                                "url": "https://example.test/app",
                                "title": "CODEVANTA Test Page",
                            }
                        ],
                    }
                replies.append(self._result(message_id, payload))
            elif method == "Page.getResourceTree":
                if self.tree == "flat":
                    payload = {"frameTree": 42}
                elif self.tree == "weird":
                    payload = {
                        "frameTree": {
                            "resources": [
                                42,
                                {"url": 5},
                                {"url": "https://example.test/ok.js", "type": "Script"},
                            ],
                            "childFrames": [
                                {
                                    "resources": [
                                        {
                                            "url": "https://example.test/child.js",
                                            "type": "Script",
                                        }
                                    ]
                                },
                                "not-a-frame",
                            ],
                        }
                }
                else:
                    payload = {
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
                    }
                replies.append(self._result(message_id, payload))
                if self.late_event and not self._stop.is_set():
                    timer = threading.Timer(
                        0.15,
                        lambda: self._push_late(conn),
                    )
                    timer.daemon = True
                    timer.start()
            elif method == "Page.captureScreenshot":
                if self.shot == "nodata":
                    replies.append(self._result(message_id, {}))
                elif self.shot == "badb64":
                    replies.append(self._result(message_id, {"data": "!!not-b64!!"}))
                else:
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
                if self.webmcp == "notlist":
                    payload = {"tools": "not-a-list"}
                elif self.webmcp == "mixed":
                    payload = {
                        "tools": [
                            "not-a-dict",
                            {"description": "no name"},
                            {"name": ""},
                            {"name": "codevanta_echo", "description": "echo a value"},
                        ]
                    }
                else:
                    payload = {
                        "tools": [
                            {"name": "codevanta_echo", "description": "echo a value"}
                        ]
                    }
                replies.append(self._result(message_id, payload))
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


# ---- pure-function gaps: frame codec and envelope edges -----------------------


def test_mask_key_must_be_four_bytes() -> None:
    """Masking with a wrong-length key is a typed protocol error."""
    with pytest.raises(CdpError, match="must be 4 bytes"):
        mask_payload(b"payload", b"abc")


def test_encode_frame_rejects_overlong_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Payloads above the message cap are refused before any frame is built."""
    monkeypatch.setattr(cdp_client, "MAX_MESSAGE_BYTES", 8)
    with pytest.raises(CdpError, match="exceeds"):
        encode_frame(OPCODE_TEXT, b"123456789")


def test_encode_frame_rejects_bad_mask_key() -> None:
    """A wrong-length pinned mask key is a typed error."""
    with pytest.raises(CdpError, match="must be 4 bytes"):
        encode_frame(OPCODE_TEXT, b"x", mask_key=b"no")


def test_frame_needs_more_prefix_variants() -> None:
    """16-bit and 64-bit length prefixes report hunger correctly."""
    assert frame_needs_more(bytes([0x81, 126]))  # length announced, bytes missing
    assert frame_needs_more(bytes([0x81, 127]) + b"\x00" * 7)
    assert frame_needs_more(b"")
    assert not frame_needs_more(bytes([0x81, 0]))


@pytest.mark.parametrize(
    "data",
    [
        b"\x81",  # header truncated
        bytes([0x81, 126]) + b"\x00",  # 16-bit length truncated
        bytes([0x81, 127]) + b"\x00" * 7,  # 64-bit length truncated
        bytes([0x81, 0x80 | 4]) + b"\x01\x02",  # mask key truncated
    ],
)
def test_decode_frame_truncation_variants_raise(data: bytes) -> None:
    """Every truncated frame shape raises the typed error."""
    with pytest.raises(CdpError, match="truncated"):
        decode_frame(data)


@pytest.mark.parametrize(
    "text",
    [
        '{"id": 1, "error": 5}',  # error payload not an object
        '{"method": "X.y", "params": 5}',  # params not an object
    ],
)
def test_parse_message_object_shape_violations(text: str) -> None:
    """Non-object result/error/params payloads are typed errors."""
    with pytest.raises(CdpError):
        parse_message(text)


def test_endpoint_normalisation_variants() -> None:
    """Bare host:port is upgraded; bad schemes and hosts are typed errors."""
    assert normalise_endpoint("127.0.0.1:9222") == "http://127.0.0.1:9222"
    assert normalise_endpoint("http://h:9/json") == "http://h:9"
    with pytest.raises(CdpError, match="must be http"):
        normalise_endpoint("ftp://h:9")
    with pytest.raises(CdpError, match="no host"):
        normalise_endpoint("http://")


def test_ws_url_parsing_variants() -> None:
    """Only plain ws:// with a host parses; everything else is a typed error."""
    assert parse_ws_url("ws://h:9/devtools/page") == ("h", 9, "/devtools/page")
    with pytest.raises(CdpError, match="only ws://"):
        parse_ws_url("wss://h:9/devtools/page")
    with pytest.raises(CdpError, match="no host"):
        parse_ws_url("ws:///devtools/page")


def test_png_dimensions_rejects_non_png() -> None:
    """Non-PNG payloads report unknown dimensions instead of raising."""
    from codevanta.analysis.cdp_client import _png_dimensions

    assert _png_dimensions(b"\x89PNG\r\n\x1a\n-short") == (None, None)
    assert _png_dimensions(b"not a png at all") == (None, None)


# ---- misbehaving debugger: scripted handshake and frame faults -----------------


class _RawWsServer:
    """A one-shot TCP stand-in that answers the WS handshake then scripts bytes.

    ``handshake`` replaces the computed 101 response (bad status, wrong
    accept key, header flood); ``script`` frames are pushed after it; the
    connection is held open so the client's deadlines decide when to stop.
    """

    def __init__(
        self,
        *,
        handshake: bytes | None = None,
        script: bytes = b"",
        hold_s: float = 1.0,
        bad_accept: bool = False,
    ) -> None:
        self.handshake = handshake
        self.script = script
        self.hold_s = hold_s
        self.bad_accept = bad_accept
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(2)
        self.port = int(self._listener.getsockname()[1])
        self.ws_url = f"ws://127.0.0.1:{self.port}/devtools/page/X"
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
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(2)
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buffer += chunk
        if self.handshake is not None:
            conn.sendall(self.handshake)
            return
        accept = self._accept_for(bytes(buffer))
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n"
        )
        if self.script:
            conn.sendall(self.script)
        deadline = time.monotonic() + self.hold_s
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                if not conn.recv(4096):
                    return
            except TimeoutError:
                continue
            except OSError:
                return

    def _accept_for(self, request: bytes) -> str:
        """The RFC 6455 accept value (or a deliberately wrong one)."""
        key = b"ignored"
        for line in request.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"sec-websocket-key":
                key = value.strip()
                break
        digest = hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        if not self.bad_accept:
            return base64.b64encode(digest).decode()
        return base64.b64encode(hashlib.sha1(b"wrong-key").digest()).decode()


def _run_ws_scenario(monkeypatch: pytest.MonkeyPatch, server: _RawWsServer) -> str:
    """Start a scripted server, probe it, and return the typed reason."""
    monkeypatch.setattr(cdp_client, "CONNECT_TIMEOUT_S", 0.5)
    server.start()
    try:
        probe = webmcp_get_tools(server.ws_url, timeout_s=0.5)
    finally:
        server.stop()
    assert not probe.available
    assert probe.tools == ()
    return probe.reason or ""


def test_ws_handshake_refused_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-101 handshake status is a typed refusal, never a traceback."""
    server = _RawWsServer(handshake=b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
    reason = _run_ws_scenario(monkeypatch, server)
    assert "refused" in reason


def test_ws_handshake_accept_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wrong Sec-WebSocket-Accept value is a typed mismatch error."""
    server = _RawWsServer(bad_accept=True)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "Sec-WebSocket-Accept mismatch" in reason


def test_ws_handshake_closed_mid_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connection closed before the handshake completes is a typed error."""
    server = _RawWsServer(handshake=b"")
    reason = _run_ws_scenario(monkeypatch, server)
    assert "closed mid-header" in reason


def test_ws_handshake_header_flood(monkeypatch: pytest.MonkeyPatch) -> None:
    """A handshake header stream without a terminator hits the 64 KiB cap."""
    flood = (b"X-Noise: " + b"a" * 512 + b"\r\n") * 130
    server = _RawWsServer(handshake=flood, hold_s=0.3)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "64 KiB" in reason


def test_ws_close_frame_ends_message_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """A peer CLOSE frame echoes back and ends the wait as a typed miss."""
    server = _RawWsServer(script=_server_frame(b"", opcode=0x8), hold_s=0.5)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "no response to WebMCP.getAllTools" in reason


def test_ws_ping_is_answered_with_pong(monkeypatch: pytest.MonkeyPatch) -> None:
    """A control-frame PING is answered and the wait still ends typed."""
    server = _RawWsServer(script=_server_frame(b"ping", opcode=0x9), hold_s=0.4)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "no response to WebMCP.getAllTools" in reason


def test_ws_double_close_hits_closed_control_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second CLOSE after the socket shut down is silently ignored."""
    script = _server_frame(b"", opcode=0x8) + _server_frame(b"", opcode=0x8)
    server = _RawWsServer(script=script, hold_s=0.5)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "no response to WebMCP.getAllTools" in reason


def test_ws_continuation_without_start_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lone CONTINUATION frame is a protocol error, reported typed."""
    server = _RawWsServer(script=_server_frame(b"orphan", opcode=0x0), hold_s=0.4)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "continuation without a started message" in reason


def test_ws_unknown_opcode_is_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unassigned opcode is a typed protocol error."""
    server = _RawWsServer(script=_server_frame(b"?", opcode=0x3), hold_s=0.4)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "unexpected WebSocket opcode" in reason


def test_ws_oversized_message_is_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reassembly above the message cap is refused before parsing."""
    monkeypatch.setattr(cdp_client, "MAX_MESSAGE_BYTES", 10)
    server = _RawWsServer(script=_server_frame(b"x" * 40), hold_s=0.4)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "exceeds" in reason


def test_ws_response_without_result_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response envelope without a result object is a typed error."""
    server = _RawWsServer(script=_server_frame(b'{"id": 1}'), hold_s=0.4)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "returned no result object" in reason


def test_ws_silence_past_deadline_is_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A channel that never answers ends the request at the deadline."""
    server = _RawWsServer(hold_s=0.6)
    reason = _run_ws_scenario(monkeypatch, server)
    assert "no response to WebMCP.getAllTools" in reason


def test_channel_send_after_close_is_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sending on a closed channel raises the typed error, not an OSError."""
    from codevanta.analysis.cdp_client import _open_channel

    monkeypatch.setattr(cdp_client, "CONNECT_TIMEOUT_S", 0.5)
    server = _RawWsServer(hold_s=1.0)
    server.start()
    try:
        channel = _open_channel(server.ws_url, 0.5)
    finally:
        server.stop()
    try:
        channel.close()
        with pytest.raises(CdpError, match="channel is closed"):
            channel.send_text("late")
    finally:
        channel.close()


# ---- inspect-page guards, degenerate payloads, observation loop -----------------


def test_inspect_page_rejects_out_of_range_options(
    fake_devtools: _FakeDevtools,
) -> None:
    """observe_ms and max_console_entries bounds are guarded up front."""
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    with pytest.raises(CdpError, match="observe_ms"):
        inspect_page(ws, observe_ms=-1)
    with pytest.raises(CdpError, match="max_console_entries"):
        inspect_page(ws, max_console_entries=0)


def test_inspect_page_drops_console_beyond_cap(fake_devtools: _FakeDevtools) -> None:
    """Console entries beyond the cap are counted as dropped, not kept."""
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    result = inspect_page(ws, observe_ms=200, max_console_entries=1)
    assert len(result.console) == 1
    assert result.console_truncated is True


def test_inspect_page_observes_late_events() -> None:
    """Events arriving during the observation window are still captured."""
    server = _FakeDevtools(late_event=True)
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=600)
    finally:
        server.stop()
    texts = [entry.text for entry in result.console]
    assert "late console traffic" in texts


def test_inspect_page_tolerates_weird_navigation_payload() -> None:
    """An index/entries mismatch degrades to empty identity strings."""
    server = _FakeDevtools(nav="weird")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=100)
    finally:
        server.stop()
    assert result.title == ""
    assert result.url == ""


def test_inspect_page_tolerates_empty_navigation_payload() -> None:
    """An empty navigation history degrades to empty identity strings."""
    server = _FakeDevtools(nav="empty")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=100)
    finally:
        server.stop()
    assert (result.title, result.url) == ("", "")


def test_inspect_page_skips_non_dict_frame_tree() -> None:
    """A frame tree that is not an object yields no resources."""
    server = _FakeDevtools(tree="flat")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=100)
    finally:
        server.stop()
    assert result.resources == ()
    assert not result.resources_truncated


def test_inspect_page_flattens_weird_resource_trees() -> None:
    """Junk resource entries are skipped; childFrames are still flattened."""
    server = _FakeDevtools(tree="weird")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=100)
    finally:
        server.stop()
    urls = [resource.url for resource in result.resources]
    assert urls == [
        "https://example.test/ok.js",
        "https://example.test/child.js",
    ]


def test_inspect_page_skips_degenerate_console_events() -> None:
    """Non-dict entries, junk args and unrelated events degrade cleanly."""
    server = _FakeDevtools(events="weird")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        result = inspect_page(ws, observe_ms=150)
    finally:
        server.stop()
    assert len(result.console) == 1
    entry = result.console[0]
    assert entry.level == "error"
    assert entry.origin == "Runtime"
    assert 'desc only str value {"k": 1}' in entry.text


def test_resource_cap_truncates_listing(
    fake_devtools: _FakeDevtools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resources above the cap stop the flatten walk with a truncation flag."""
    monkeypatch.setattr(cdp_client, "MAX_RESOURCES", 1)
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    result = inspect_page(ws, observe_ms=100)
    assert result.resources_truncated is True
    assert len(result.resources) == 1


# ---- screenshot guards and payload JSON records --------------------------------


def test_screenshot_result_record_is_json_safe(
    fake_devtools: _FakeDevtools, tmp_path: Path
) -> None:
    """The screenshot record round-trips through to_dict() as JSON."""
    out = tmp_path / "shot.jsonsafe.png"
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    record = capture_screenshot(ws, out)
    payload = record.to_dict()
    json.dumps(payload)
    assert payload["bytes"] == len(_png_1x1())
    assert payload["width"] == 1 and payload["height"] == 1


def test_screenshot_without_data_is_typed() -> None:
    """A capture reply without a data string is a typed error."""
    server = _FakeDevtools(shot="nodata")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        with pytest.raises(CdpError, match="no data"):
            capture_screenshot(ws, Path("unused.png"))
    finally:
        server.stop()


def test_screenshot_bad_base64_is_typed() -> None:
    """A capture payload that is not base64 is a typed error."""
    server = _FakeDevtools(shot="badb64")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        with pytest.raises(CdpError, match="not base64"):
            capture_screenshot(ws, Path("unused.png"))
    finally:
        server.stop()


def test_screenshot_above_cap_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A payload above the screenshot cap is refused before any write."""
    monkeypatch.setattr(cdp_client, "MAX_SCREENSHOT_BYTES", 8)
    server = _FakeDevtools()
    server.start()
    try:
        out = tmp_path / "never.png"
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        with pytest.raises(CdpError, match="screenshot payload"):
            capture_screenshot(ws, out)
        assert not out.exists()
    finally:
        server.stop()


def test_screenshot_unwritable_target_is_typed(
    fake_devtools: _FakeDevtools, tmp_path: Path
) -> None:
    """An unwritable output path surfaces as a typed error."""
    out = tmp_path / "occupied"  # a directory: write_bytes must fail
    out.mkdir()
    ws = f"ws://127.0.0.1:{fake_devtools.port}/devtools/page/PAGE1"
    with pytest.raises(CdpError, match="cannot write screenshot"):
        capture_screenshot(ws, out)


# ---- /json list decoding guards -------------------------------------------------


class _JsonServer:
    """A minimal HTTP stand-in returning one fixed body for every GET."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port = int(self._listener.getsockname()[1])
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
                conn.recv(4096)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(self.body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + self.body
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


def test_list_targets_rejects_invalid_json() -> None:
    """A /json body that is not JSON is a typed error."""
    server = _JsonServer(b"definitely not json")
    server.start()
    try:
        with pytest.raises(CdpError, match="not valid JSON"):
            list_targets(server.endpoint)
    finally:
        server.stop()


def test_list_targets_rejects_non_array_json() -> None:
    """A /json body that is not an array is a typed error."""
    server = _JsonServer(b'{"nope": true}')
    server.start()
    try:
        with pytest.raises(CdpError, match="not a JSON array"):
            list_targets(server.endpoint)
    finally:
        server.stop()


def test_list_targets_skips_unusable_entries() -> None:
    """Non-object entries and entries without ids are skipped silently."""
    body = json.dumps(
        [
            42,
            {"type": "page"},  # no id
            {"id": "OK1", "type": "page", "title": "kept"},
        ]
    ).encode()
    server = _JsonServer(body)
    server.start()
    try:
        listing = list_targets(server.endpoint)
    finally:
        server.stop()
    assert [t.target_id for t in listing.targets] == ["OK1"]
    assert listing.targets[0].ws_url is None


def test_list_targets_enforces_body_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Target lists above the read cap are refused before parsing."""
    monkeypatch.setattr(cdp_client, "_MAX_TARGETS_BODY_BYTES", 32)
    server = _JsonServer(json.dumps([{"id": "BIG"}] * 20).encode())
    server.start()
    try:
        with pytest.raises(CdpError, match="read cap"):
            list_targets(server.endpoint)
    finally:
        server.stop()


# ---- WebMCP tool payload shapes --------------------------------------------------


def test_webmcp_tools_not_a_list_is_available_but_empty() -> None:
    """A tools field that is not a list yields an empty, available probe."""
    server = _FakeDevtools(webmcp="notlist")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        probe = webmcp_get_tools(ws)
    finally:
        server.stop()
    assert probe.available
    assert probe.tools == ()
    assert probe.to_dict()["tool_count"] == 0


def test_webmcp_tool_entries_without_names_are_skipped() -> None:
    """Non-object and name-less tool entries are skipped from the list."""
    server = _FakeDevtools(webmcp="mixed")
    server.start()
    try:
        ws = f"ws://127.0.0.1:{server.port}/devtools/page/PAGE1"
        probe = webmcp_get_tools(ws)
    finally:
        server.stop()
    assert probe.available
    assert [tool.name for tool in probe.tools] == ["codevanta_echo"]
    record = probe.tools[0].to_dict()
    assert record == {"name": "codevanta_echo", "description": "echo a value"}


# ---- CLI render paths (text + --json) ------------------------------------------


def test_cli_web_targets_json(fake_devtools: _FakeDevtools) -> None:
    """``web targets --json`` emits the unchanged target payload."""
    result = runner.invoke(
        cli_app, ["web", "targets", "--endpoint", fake_devtools.endpoint, "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["targets"][0]["id"] == "PAGE1"


def test_cli_web_inspect_text_render(fake_devtools: _FakeDevtools) -> None:
    """``web inspect`` without --json renders tables and a totals footer."""
    result = runner.invoke(
        cli_app,
        [
            "web",
            "inspect",
            "PAGE1",
            "--endpoint",
            fake_devtools.endpoint,
            "--observe-ms",
            "200",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "title:" in result.output
    assert "CODEVANTA Test Page" in result.output
    assert "Resources" in result.output
    assert "resources: 2 (truncated: no)" in result.output
    assert "console: 3 entries" in result.output


def test_cli_web_inspect_unknown_target_exits_two(fake_devtools: _FakeDevtools) -> None:
    """Inspecting an unknown target id is a typed exit 2."""
    result = runner.invoke(
        cli_app, ["web", "inspect", "GONE", "--endpoint", fake_devtools.endpoint]
    )
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_web_inspect_target_without_ws_url() -> None:
    """A page target without a debugger URL is a typed exit 2."""
    server = _FakeDevtools(
        extra_targets=({"id": "NOWS", "type": "page", "title": "bare"},)
    )
    server.start()
    try:
        result = runner.invoke(
            cli_app, ["web", "inspect", "NOWS", "--endpoint", server.endpoint]
        )
    finally:
        server.stop()
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_web_webmcp_text_unavailable(fake_devtools: _FakeDevtools) -> None:
    """The webmcp probe prints a yellow absence line without --json."""
    result = runner.invoke(
        cli_app,
        ["web", "webmcp", "PAGE1", "--endpoint", fake_devtools.endpoint],
    )
    assert result.exit_code == 0, result.output
    assert "WebMCP unavailable" in result.output
    assert "available: no" in result.output


def test_cli_web_webmcp_text_available() -> None:
    """A present WebMCP domain lists tools in text mode."""
    server = _FakeDevtools(webmcp="present")
    server.start()
    try:
        result = runner.invoke(
            cli_app, ["web", "webmcp", "PAGE1", "--endpoint", server.endpoint]
        )
        as_json = runner.invoke(
            cli_app, ["web", "webmcp", "PAGE1", "--endpoint", server.endpoint, "--json"]
        )
    finally:
        server.stop()
    assert result.exit_code == 0, result.output
    assert "WebMCP tools:" in result.output
    assert "codevanta_echo" in result.output
    assert "available: yes" in result.output
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.output)
    assert payload["tool_count"] == 1


def test_cli_web_shot_failure_exits_two() -> None:
    """A failed capture is a one-line typed error with exit code 2."""
    server = _FakeDevtools(shot="nodata")
    server.start()
    try:
        result = runner.invoke(
            cli_app, ["web", "shot", "PAGE1", "out.png", "--endpoint", server.endpoint]
        )
    finally:
        server.stop()
    assert result.exit_code == 2
    assert "error:" in result.output


def test_cli_web_asar_truncation_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``asar`` text mode warns when the listing hit the file cap."""
    from codevanta.analysis import asar as asar_module

    monkeypatch.setattr(asar_module, "MAX_FILES", 2)
    files = {f"m{index}.js": b"// script" for index in range(4)}
    archive, _ = _build_asar(tmp_path, files)
    result = runner.invoke(cli_app, ["asar", str(archive)])
    assert result.exit_code == 0, result.output
    assert "truncated: yes" in result.output
    assert "warning:" in result.output


# ---- MCP tool layer (`codevanta_web_inspect` / `codevanta_asar`) -----------------


def test_mcp_web_inspect_payload_fields(fake_devtools: _FakeDevtools) -> None:
    """The skip-gated inspect returns an available payload with identity."""
    payload = mcp_tools.codevanta_web_inspect(endpoint=fake_devtools.endpoint)
    assert payload["available"] is True
    assert payload["title"] == "CODEVANTA Test Page"
    assert payload["target_id"] == "PAGE1"
    assert payload["endpoint"] == fake_devtools.endpoint


def test_mcp_web_inspect_unknown_target_is_unavailable(
    fake_devtools: _FakeDevtools,
) -> None:
    """An unknown target id degrades to the typed unavailable payload."""
    payload = mcp_tools.codevanta_web_inspect(
        endpoint=fake_devtools.endpoint, target_id="GONE"
    )
    assert payload["available"] is False
    assert "not found" in payload["reason"]
    assert payload["evidence"]["confidence"] == "low"


def test_mcp_web_inspect_rejects_bad_endpoint() -> None:
    """An empty endpoint is a typed AnalysisError, not a skip result."""
    with pytest.raises(AnalysisError, match="endpoint must be"):
        mcp_tools.codevanta_web_inspect(endpoint="   ")


def test_mcp_web_inspect_without_page_target_is_unavailable() -> None:
    """An endpoint with no page targets degrades to unavailable."""
    body = json.dumps([{"id": "S1", "type": "service"}]).encode()
    server = _JsonServer(body)
    server.start()
    try:
        payload = mcp_tools.codevanta_web_inspect(endpoint=server.endpoint)
    finally:
        server.stop()
    assert payload["available"] is False
    assert "no inspectable page target" in payload["reason"]


def test_mcp_web_inspect_without_ws_url_is_unavailable() -> None:
    """A page target without a debugger URL degrades to unavailable."""
    body = json.dumps([{"id": "P1", "type": "page", "title": "bare"}]).encode()
    server = _JsonServer(body)
    server.start()
    try:
        payload = mcp_tools.codevanta_web_inspect(
            endpoint=server.endpoint, target_id="P1"
        )
    finally:
        server.stop()
    assert payload["available"] is False
    assert "no debugger websocket" in payload["reason"]


def test_mcp_web_inspect_dead_ws_is_unavailable() -> None:
    """A debugger socket that refuses connections degrades to unavailable."""
    body = json.dumps(
        [
            {
                "id": "P1",
                "type": "page",
                "webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/page/P1",
            }
        ]
    ).encode()
    server = _JsonServer(body)
    server.start()
    try:
        payload = mcp_tools.codevanta_web_inspect(endpoint=server.endpoint)
    finally:
        server.stop()
    assert payload["available"] is False
    assert "cannot connect" in payload["reason"]


def test_mcp_asar_path_argument_validation(tmp_path: Path) -> None:
    """Non-string, empty and non-file paths are typed errors."""
    with pytest.raises(AnalysisError, match="must be a string"):
        mcp_tools.codevanta_asar(42)  # type: ignore[arg-type]
    with pytest.raises(AnalysisError, match="must not be empty"):
        mcp_tools.codevanta_asar("   ")
    with pytest.raises(AnalysisError, match="not a regular file"):
        mcp_tools.codevanta_asar(str(tmp_path))


def test_mcp_asar_rejects_non_string_extract(tmp_path: Path) -> None:
    """A non-string extract argument is a typed error."""
    archive, _ = _build_asar(tmp_path, _MINIMAL_FILES)
    with pytest.raises(AnalysisError, match="extract must be a string"):
        mcp_tools.codevanta_asar(str(archive), extract=3)  # type: ignore[arg-type]



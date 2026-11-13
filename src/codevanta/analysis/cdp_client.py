"""Minimal Chrome DevTools Protocol client (stdlib only, passive inspection).

This lane inspects a live Electron/Chromium *without executing anything in it*.
The only protocol messages ever sent are domain enables and read-only queries
(``Page.enable``, ``Log.enable``, ``Runtime.enable``,
``Page.getNavigationHistory``, ``Page.getResourceTree``,
``Page.captureScreenshot``). ``Runtime.evaluate`` is deliberately absent: one
wrong "harmless" expression can mutate a live target, so the API surface makes
it unreachable.

Everything is bounded and offline-typed:

* The WebSocket layer (RFC 6455 client) is implemented over plain sockets, so
  the lane adds no dependency: handshake (``Sec-WebSocket-Key``/``Accept``),
  masked client frames, fragmentation, ping/pong, close handshake, and a
  hard :data:`MAX_MESSAGE_BYTES` (4 MiB) cap per message.
* Every socket operation runs under a deadline; observation windows default
  to :data:`DEFAULT_OBSERVE_MS` and are capped at :data:`MAX_OBSERVE_MS`.
* A dead endpoint raises the typed :class:`CdpError` (a subclass of
  :class:`~codevanta.core.report.AnalysisError`), never a raw socket
  traceback -- callers such as the MCP tool turn it into a typed
  ``available: false`` result instead of crashing.
* The WebMCP probe (:func:`webmcp_get_tools`) sends ``WebMCP.getAllTools``
  and tolerates the unknown-domain ``-32601`` reply as a first-class,
  typed "domain unavailable" outcome.

Pure pieces (frame codec, CDP message envelope) are module-level functions so
tests can exercise them without any socket at all.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "CONNECT_TIMEOUT_S",
    "DEFAULT_ENDPOINT",
    "DEFAULT_OBSERVE_MS",
    "MAX_CONSOLE_ENTRIES",
    "MAX_MESSAGE_BYTES",
    "MAX_OBSERVE_MS",
    "MAX_RESOURCES",
    "MAX_SCREENSHOT_BYTES",
    "MAX_TARGETS",
    "CdpConsoleEntry",
    "CdpError",
    "CdpInspect",
    "CdpMessage",
    "CdpResource",
    "CdpScreenshot",
    "CdpTarget",
    "CdpTargets",
    "Frame",
    "OPCODE_CLOSE",
    "OPCODE_CONTINUATION",
    "OPCODE_PING",
    "OPCODE_PONG",
    "OPCODE_TEXT",
    "WebMcpProbe",
    "WebMcpTool",
    "capture_screenshot",
    "decode_frame",
    "encode_frame",
    "encode_request",
    "find_target",
    "frame_needs_more",
    "inspect_page",
    "list_targets",
    "mask_payload",
    "parse_message",
    "webmcp_get_tools",
]

#: RFC 6455 frame opcodes used by this lane.
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

#: Hard cap on one WebSocket message (assembled, unmasked): 4 MiB.
MAX_MESSAGE_BYTES = 4 * 1024 * 1024

#: Hard cap on a decoded screenshot payload: 20 MiB PNG.
MAX_SCREENSHOT_BYTES = 20 * 1024 * 1024

#: Hard cap on targets listed from one ``/json`` call.
MAX_TARGETS = 100

#: Hard cap on resources reported by one inspection.
MAX_RESOURCES = 200

#: Hard cap on console entries collected during one inspection.
MAX_CONSOLE_ENTRIES = 200

#: Default observation window for console/log capture (mission default 2000ms).
DEFAULT_OBSERVE_MS = 2000

#: Hard ceiling on the observation window (bounded work).
MAX_OBSERVE_MS = 30_000

#: Default CDP HTTP endpoint (Chromium's ``--remote-debugging-port`` default).
DEFAULT_ENDPOINT = "http://127.0.0.1:9222"

#: Connect/handshake timeout in seconds; every socket op is at most this
#: plus the remaining observation budget, so nothing hangs forever.
CONNECT_TIMEOUT_S = 3.0

#: Extra wall-clock slack granted to the three setup round-trips of an
#: inspection beyond the observation window itself.
INSPECT_SLACK_S = 2.0

#: RFC 6455 fixed GUID appended to the handshake key.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#: Hard cap on the raw ``/json`` body read (1 MiB is far beyond Chromium's).
_MAX_TARGETS_BODY_BYTES = 1024 * 1024

_UINT16 = struct.Struct(">H")
_UINT64 = struct.Struct(">Q")


class CdpError(AnalysisError):
    """Typed failure of a CDP/WebSocket operation (endpoint down, timeout,
    protocol violation). Callers catch :class:`AnalysisError` and still get
    this more specific type for skip-gating decisions."""


@dataclass(frozen=True)
class Frame:
    """One decoded WebSocket frame.

    Attributes:
        fin: True when the FIN bit is set (final fragment of a message).
        opcode: RFC 6455 opcode (see the ``OPCODE_*`` constants).
        payload: Unmasked payload bytes.
        consumed: Bytes of the input buffer this frame occupies, so callers
            can drop exactly what they parsed.
    """

    fin: bool
    opcode: int
    payload: bytes
    consumed: int


def mask_payload(payload: bytes, key: bytes) -> bytes:
    """XOR ``payload`` with the 4-byte frame ``key`` (RFC 6455 masking).

    Masking is symmetric, so this both masks client frames and unmasks
    server frames. Pure function, no I/O.
    """
    if len(key) != 4:
        raise CdpError(f"WebSocket mask key must be 4 bytes, got {len(key)}")
    return bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))


def encode_frame(
    opcode: int,
    payload: bytes = b"",
    *,
    mask_key: bytes | None = None,
) -> bytes:
    """Encode one client-to-server WebSocket frame.

    Client frames are always masked (RFC 6455 servers must reject unmasked
    client frames); ``mask_key`` pins the key for deterministic tests, and
    ``None`` draws a fresh random key. Raises :class:`CdpError` for payloads
    above :data:`MAX_MESSAGE_BYTES` or a malformed key.
    """
    if len(payload) > MAX_MESSAGE_BYTES:
        raise CdpError(
            f"frame payload {len(payload)} bytes exceeds {MAX_MESSAGE_BYTES}"
        )
    key = secrets.token_bytes(4) if mask_key is None else mask_key
    if len(key) != 4:
        raise CdpError(f"WebSocket mask key must be 4 bytes, got {len(key)}")
    first = 0x80 | (opcode & 0x0F)  # FIN + opcode (no RSV bits, no fragments)
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])  # MASK bit + 7-bit length
    elif length <= 0xFFFF:
        header = bytes([first, 0x80 | 126]) + _UINT16.pack(length)
    else:
        header = bytes([first, 0x80 | 127]) + _UINT64.pack(length)
    return header + key + mask_payload(payload, key)


def frame_needs_more(data: bytes) -> bool:
    """True when ``data`` cannot yet contain a complete frame.

    Cheap prefix arithmetic (header + declared payload length + mask key),
    used by the receive loop to decide whether another ``recv`` is required
    before the full :func:`decode_frame` runs.
    """
    if len(data) < 2:
        return True
    length = data[1] & 0x7F
    pos = 2
    if length == 126:
        if len(data) < pos + 2:
            return True
        length = _UINT16.unpack_from(data, pos)[0]
        pos += 2
    elif length == 127:
        if len(data) < pos + 8:
            return True
        length = _UINT64.unpack_from(data, pos)[0]
        pos += 8
    if data[1] & 0x80:
        pos += 4
    return len(data) < pos + length


def decode_frame(data: bytes) -> Frame:
    """Decode one complete WebSocket frame from the head of ``data``.

    Pure function over bytes. Raises :class:`CdpError` for malformed or
    incomplete input, and refuses frames whose payload would exceed
    :data:`MAX_MESSAGE_BYTES` before any byte is copied.
    """
    if len(data) < 2:
        raise CdpError(f"truncated WebSocket frame header: {len(data)} bytes")
    first, second = data[0], data[1]
    if first & 0x70:
        raise CdpError("WebSocket frame sets reserved RSV bits")
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    pos = 2
    if length == 126:
        if len(data) < pos + 2:
            raise CdpError("truncated WebSocket 16-bit length")
        length = _UINT16.unpack_from(data, pos)[0]
        pos += 2
    elif length == 127:
        if len(data) < pos + 8:
            raise CdpError("truncated WebSocket 64-bit length")
        length = _UINT64.unpack_from(data, pos)[0]
        pos += 8
    if length > MAX_MESSAGE_BYTES:
        raise CdpError(
            f"WebSocket frame of {length} bytes exceeds {MAX_MESSAGE_BYTES}"
        )
    key = b""
    if masked:
        if len(data) < pos + 4:
            raise CdpError("truncated WebSocket mask key")
        key = data[pos : pos + 4]
        pos += 4
    end = pos + length
    if len(data) < end:
        raise CdpError(f"incomplete WebSocket frame: need {end}, have {len(data)}")
    payload = data[pos:end]
    if masked:
        payload = mask_payload(payload, key)
    return Frame(fin=fin, opcode=opcode, payload=payload, consumed=end)


@dataclass(frozen=True)
class CdpMessage:
    """One decoded CDP JSON message (response or event).

    Attributes:
        message_id: Response id, or None for events.
        method: Event method name, or None for responses.
        result: Response ``result`` payload (dict) when present.
        error: Response ``error`` payload (dict) when present.
        params: Event ``params`` payload (dict) when present.
    """

    message_id: int | None
    method: str | None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    params: dict[str, Any] | None = None

    @property
    def is_event(self) -> bool:
        """True when this message is an event (no id)."""
        return self.message_id is None and self.method is not None


def encode_request(message_id: int, method: str, params: dict[str, Any] | None = None) -> str:
    """Encode a CDP request envelope as JSON text (pure function)."""
    message: dict[str, Any] = {"id": message_id, "method": method}
    if params:
        message["params"] = params
    return json.dumps(message, ensure_ascii=False)


def parse_message(text: str) -> CdpMessage:
    """Parse one CDP JSON message (pure function).

    Accepts the two shapes the protocol defines -- responses (``id`` plus
    ``result`` or ``error``) and events (``method`` plus ``params``) -- and
    raises :class:`CdpError` for anything else, so malformed input can never
    slip through as a silent None.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CdpError(f"CDP message is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CdpError("CDP message must be a JSON object")
    if "id" in payload:
        message_id = payload["id"]
        if isinstance(message_id, bool) or not isinstance(message_id, int):
            raise CdpError(f"CDP response id must be an integer, got {message_id!r}")
        result = payload.get("result")
        error = payload.get("error")
        if result is not None and not isinstance(result, dict):
            raise CdpError("CDP response result must be an object")
        if error is not None and not isinstance(error, dict):
            raise CdpError("CDP response error must be an object")
        return CdpMessage(message_id=message_id, method=None, result=result, error=error)
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise CdpError(f"CDP event without a method name: {payload!r}")
    params = payload.get("params")
    if params is not None and not isinstance(params, dict):
        raise CdpError("CDP event params must be an object")
    return CdpMessage(message_id=None, method=method, params=params)


@dataclass(frozen=True)
class CdpTarget:
    """One target from the DevTools ``/json`` list."""

    target_id: str
    type: str
    title: str
    url: str
    ws_url: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "id": self.target_id,
            "type": self.type,
            "title": self.title,
            "url": self.url,
            "webSocketDebuggerUrl": self.ws_url,
        }


@dataclass(frozen=True)
class CdpTargets:
    """Bounded listing of one endpoint's debug targets."""

    endpoint: str
    targets: tuple[CdpTarget, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "endpoint": self.endpoint,
            "count": len(self.targets),
            "targets": [target.to_dict() for target in self.targets],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class CdpResource:
    """One resource from the page's frame tree."""

    url: str
    type: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {"url": self.url, "type": self.type}


@dataclass(frozen=True)
class CdpConsoleEntry:
    """One console/log line observed passively (never requested)."""

    level: str
    text: str
    origin: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {"level": self.level, "text": self.text, "source": self.origin}


@dataclass(frozen=True)
class CdpInspect:
    """Passive inspection of one page: identity, resources, console traffic.

    Everything here was read or merely overheard: navigation state, the
    resource tree, and ``Log.entryAdded`` / ``Runtime.consoleAPICalled``
    events during the observation window. No script was evaluated.
    """

    title: str
    url: str
    resources: tuple[CdpResource, ...]
    resources_truncated: bool
    console: tuple[CdpConsoleEntry, ...]
    console_truncated: bool
    observe_ms: int
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "title": self.title,
            "url": self.url,
            "resource_count": len(self.resources),
            "resources_truncated": self.resources_truncated,
            "resources": [resource.to_dict() for resource in self.resources],
            "console_count": len(self.console),
            "console_truncated": self.console_truncated,
            "console": [entry.to_dict() for entry in self.console],
            "observe_ms": self.observe_ms,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class CdpScreenshot:
    """One ``Page.captureScreenshot`` PNG written to disk (bounded 20 MiB)."""

    path: str
    byte_count: int
    width: int | None
    height: int | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "path": self.path,
            "bytes": self.byte_count,
            "width": self.width,
            "height": self.height,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class WebMcpTool:
    """One tool advertised by the (optional) WebMCP domain."""

    name: str
    description: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {"name": self.name, "description": self.description}


@dataclass(frozen=True)
class WebMcpProbe:
    """Typed result of probing the WebMCP domain on one target.

    ``available`` is False -- never an exception -- when the target answers
    ``-32601`` (unknown domain), stays silent, or cannot be reached at all;
    ``reason`` says which. This is the skip-gate contract of the lane.
    """

    available: bool
    reason: str | None
    tools: tuple[WebMcpTool, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "available": self.available,
            "reason": self.reason,
            "tool_count": len(self.tools),
            "tools": [tool.to_dict() for tool in self.tools],
            "evidence": self.evidence.to_dict(),
        }


def normalise_endpoint(endpoint: str) -> str:
    """Normalise a DevTools HTTP endpoint to its ``http(s)://host:port`` base.

    Accepts ``host:port``, ``http://host:port``, a trailing slash, or an
    endpoint that already names ``/json``; raises :class:`CdpError` for
    anything that is not an HTTP(S) URL with a host, so the ``/json`` suffix
    is appended exactly once.
    """
    text = endpoint.strip()
    if "://" not in text:
        text = f"http://{text}"
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise CdpError(
            f"CDP endpoint must be http(s), got scheme {parts.scheme!r} in {endpoint!r}"
        )
    if not parts.hostname:
        raise CdpError(f"CDP endpoint has no host: {endpoint!r}")
    base = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    if path.endswith("/json"):
        path = path[: -len("/json")]
    return base + path


def parse_ws_url(ws_url: str) -> tuple[str, int, str]:
    """Split a ``ws://host:port/path`` debugger URL into host, port, path.

    ``wss://`` is refused with a typed error: this lane runs on plain
    sockets and never pretends to do TLS.
    """
    parts = urlsplit(ws_url.strip())
    if parts.scheme != "ws":
        raise CdpError(
            "only ws:// debugger URLs are supported (stdlib-only lane), "
            f"got {parts.scheme!r} in {ws_url!r}"
        )
    if not parts.hostname:
        raise CdpError(f"debugger URL has no host: {ws_url!r}")
    port = parts.port or 80
    path = parts.path or "/"
    return parts.hostname, port, path


class _WsChannel:
    """One RFC 6455 WebSocket connection to a DevTools debugger URL.

    Implemented over a plain socket (no dependency): client frames are
    masked, server frames are unmasked, ping is answered with pong, the
    close handshake is performed when the peer closes, and every receive
    runs against a wall-clock deadline so a wedged target cannot hang the
    lane. Assembled messages are capped at :data:`MAX_MESSAGE_BYTES`.
    """

    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout_s: float = CONNECT_TIMEOUT_S,
    ) -> None:
        self._timeout_s = timeout_s
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._closed = False
        try:
            sock = socket.create_connection((host, port), timeout=timeout_s)
        except OSError as exc:
            raise CdpError(f"cannot connect to ws://{host}:{port}: {exc}") from exc
        self._sock = sock
        try:
            self._handshake(host, port, path)
        except Exception:
            self.close()
            raise

    def deadline(self, seconds: float) -> float:
        """Return a wall-clock deadline ``seconds`` from now."""
        return time.monotonic() + max(seconds, 0.0)

    def send_text(self, text: str) -> None:
        """Send one complete text message as a single masked frame."""
        if self._sock is None or self._closed:
            raise CdpError("WebSocket channel is closed")
        payload = text.encode("utf-8")
        try:
            self._sock.sendall(encode_frame(OPCODE_TEXT, payload))
        except OSError as exc:
            raise CdpError(f"WebSocket send failed: {exc}") from exc

    def next_message(self, deadline: float) -> CdpMessage | None:
        """Receive the next CDP message, or None past ``deadline``/on close.

        Control frames are handled inside the loop: ping is answered with a
        pong, a close frame triggers the closing half of the close handshake
        and ends the loop. Text messages are reassembled across continuation
        fragments under the :data:`MAX_MESSAGE_BYTES` cap, then parsed with
        :func:`parse_message`.
        """
        fragments: list[bytes] = []
        first_opcode = OPCODE_CONTINUATION
        total = 0
        while True:
            frame = self._next_frame(deadline)
            if frame is None:
                return None
            if frame.opcode == OPCODE_CLOSE:
                self._respond_close(frame.payload)
                return None
            if frame.opcode == OPCODE_PING:
                self._send_control(OPCODE_PONG, frame.payload)
                continue
            if frame.opcode == OPCODE_PONG:
                continue
            if frame.opcode == OPCODE_TEXT:
                fragments = [frame.payload]
                first_opcode = OPCODE_TEXT
                total = len(frame.payload)
            elif frame.opcode == OPCODE_CONTINUATION:
                if not fragments:
                    raise CdpError("WebSocket continuation without a started message")
                fragments.append(frame.payload)
                total += len(frame.payload)
            else:
                raise CdpError(f"unexpected WebSocket opcode {frame.opcode}")
            if total > MAX_MESSAGE_BYTES:
                raise CdpError(f"WebSocket message exceeds {MAX_MESSAGE_BYTES} bytes")
            if frame.fin:
                if first_opcode != OPCODE_TEXT:
                    raise CdpError("WebSocket message ended without text opcode")
                return parse_message(b"".join(fragments).decode("utf-8"))

    def close(self) -> None:
        """Close the socket (best effort; never raises)."""
        if self._sock is not None and not self._closed:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # -- internals -------------------------------------------------------

    def _handshake(self, host: str, port: int, path: str) -> None:
        """Run the RFC 6455 opening handshake and verify the accept key."""
        assert self._sock is not None
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        try:
            self._sock.sendall(request.encode("ascii"))
            raw = self._read_until(b"\r\n\r\n", self.deadline(self._timeout_s))
        except OSError as exc:
            raise CdpError(f"WebSocket handshake failed: {exc}") from exc
        expected = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        head = raw.decode("latin-1")
        lines = head.split("\r\n")
        status = lines[0] if lines else ""
        if " 101 " not in f" {status} " and not status.endswith(" 101"):
            raise CdpError(f"WebSocket handshake refused: {status!r}")
        accept = None
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "sec-websocket-accept":
                accept = value.strip()
                break
        if accept != expected:
            raise CdpError(
                "WebSocket handshake Sec-WebSocket-Accept mismatch "
                f"(got {accept!r}, expected {expected!r})"
            )

    def _read_until(self, marker: bytes, deadline: float) -> bytes:
        """Buffer bytes until ``marker`` appears (handshake header read)."""
        while marker not in self._buf:
            if not self._recv_chunk(deadline):
                raise CdpError("WebSocket handshake: connection closed mid-header")
            if len(self._buf) > 65_536:
                raise CdpError("WebSocket handshake header exceeds 64 KiB")
        end = self._buf.index(marker) + len(marker)
        raw = bytes(self._buf[:end])
        del self._buf[:end]
        return raw

    def _recv_chunk(self, deadline: float) -> bool:
        """One bounded ``recv`` into the buffer; False past deadline/close."""
        assert self._sock is not None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._sock.settimeout(min(remaining, self._timeout_s))
        try:
            chunk = self._sock.recv(65_536)
        except TimeoutError:
            return False
        except OSError as exc:
            raise CdpError(f"WebSocket receive failed: {exc}") from exc
        if not chunk:
            return False
        self._buf += chunk
        return True

    def _next_frame(self, deadline: float) -> Frame | None:
        """Next complete frame from the buffer, or None past deadline/close."""
        while True:
            if not frame_needs_more(bytes(self._buf)):
                frame = decode_frame(bytes(self._buf))
                del self._buf[: frame.consumed]
                return frame
            if not self._recv_chunk(deadline):
                return None

    def _send_control(self, opcode: int, payload: bytes) -> None:
        """Send one control frame (pong/close); failures end the channel."""
        if self._sock is None or self._closed:
            return
        try:
            self._sock.sendall(encode_frame(opcode, payload[:125]))
        except OSError:
            self.close()

    def _respond_close(self, payload: bytes) -> None:
        """Echo the peer's close frame, then shut the socket down."""
        self._send_control(OPCODE_CLOSE, payload)
        self._closed = True
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def _open_channel(ws_url: str, timeout_s: float) -> _WsChannel:
    """Open a :class:`_WsChannel` from a debugger URL (typed failures)."""
    host, port, path = parse_ws_url(ws_url)
    return _WsChannel(host, port, path, timeout_s=timeout_s)


def _request(
    channel: _WsChannel,
    message_id: int,
    method: str,
    params: dict[str, Any] | None,
    deadline: float,
    sink: list[CdpMessage],
) -> dict[str, Any]:
    """Send one request and wait for its response (bounded).

    Events observed while waiting go into ``sink`` so the caller's
    observation loop never loses console traffic that arrives early.
    """
    channel.send_text(encode_request(message_id, method, params))
    while True:
        message = channel.next_message(deadline)
        if message is None:
            raise CdpError(f"no response to {method} before the deadline")
        if message.message_id == message_id:
            if message.error is not None:
                code = message.error.get("code")
                text = message.error.get("message", "")
                raise CdpError(f"{method} failed (code {code}): {text}")
            if message.result is None:
                raise CdpError(f"{method} returned no result object")
            return message.result
        if message.method is not None:
            sink.append(message)


def list_targets(
    endpoint: str = DEFAULT_ENDPOINT,
    *,
    timeout_s: float = CONNECT_TIMEOUT_S,
) -> CdpTargets:
    """List one endpoint's debug targets via the HTTP ``/json`` list.

    Read-only HTTP GET; nothing connects to the debugger socket here.
    Raises :class:`CdpError` (a typed :class:`AnalysisError`) when the
    endpoint is unreachable, the body is oversized, or the JSON is not a
    list of objects.
    """
    base = normalise_endpoint(endpoint)
    url = f"{base}/json"
    try:
        with urlopen(url, timeout=timeout_s) as response:
            raw = response.read(_MAX_TARGETS_BODY_BYTES + 1)
    except (URLError, OSError, ValueError) as exc:
        raise CdpError(f"CDP endpoint {url} unreachable: {exc}") from exc
    if len(raw) > _MAX_TARGETS_BODY_BYTES:
        raise CdpError(f"CDP target list from {url} exceeds the read cap")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CdpError(f"CDP target list from {url} is not valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise CdpError(f"CDP target list from {url} is not a JSON array")
    targets: list[CdpTarget] = []
    for item in payload[:MAX_TARGETS]:
        if not isinstance(item, dict):
            continue
        target_id = item.get("id")
        if not isinstance(target_id, str) or not target_id:
            continue
        ws_url = item.get("webSocketDebuggerUrl")
        targets.append(
            CdpTarget(
                target_id=target_id,
                type=str(item.get("type", "unknown")),
                title=str(item.get("title", "")),
                url=str(item.get("url", "")),
                ws_url=ws_url if isinstance(ws_url, str) else None,
            )
        )
    evidence = Evidence(
        source="cdp.inspect",
        method="http_json_list",
        confidence=Confidence.HIGH,
        extra={"endpoint": url, "count": len(targets)},
    )
    return CdpTargets(endpoint=base, targets=tuple(targets), evidence=evidence)


def find_target(targets: CdpTargets, target_id: str) -> CdpTarget:
    """Find one target by id; typed error naming a few known ids otherwise."""
    for target in targets.targets:
        if target.target_id == target_id:
            return target
    known = ", ".join(repr(t.target_id) for t in targets.targets[:5])
    raise CdpError(
        f"target {target_id!r} not found on {targets.endpoint}; known: {known}"
    )


def _flatten_resources(frame_tree: Any) -> tuple[tuple[CdpResource, ...], bool]:
    """Flatten a ``Page.getResourceTree`` frame tree into bounded resources.

    Walks nested ``childFrames`` iteratively and collects each frame's
    ``resources`` entries (url/type) up to :data:`MAX_RESOURCES`.
    """
    resources: list[CdpResource] = []
    stack = [frame_tree]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for item in node.get("resources", []) or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            if not isinstance(url, str) or not url:
                continue
            if len(resources) >= MAX_RESOURCES:
                return tuple(resources), True
            kind = item.get("type")
            resources.append(
                CdpResource(url=url, type=kind if isinstance(kind, str) else "other")
            )
        children = node.get("childFrames")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
    return tuple(resources), False


def _console_entry_from_event(message: CdpMessage) -> CdpConsoleEntry | None:
    """Turn a ``Log.entryAdded`` or ``Runtime.consoleAPICalled`` event into a
    bounded, JSON-safe console entry; None for anything else."""
    params = message.params or {}
    if message.method == "Log.entryAdded":
        entry = params.get("entry")
        if not isinstance(entry, dict):
            return None
        level = entry.get("level")
        text = entry.get("text")
        origin = entry.get("source")
        return CdpConsoleEntry(
            level=level if isinstance(level, str) else "info",
            text=text if isinstance(text, str) else "",
            origin=origin if isinstance(origin, str) else "Log",
        )
    if message.method == "Runtime.consoleAPICalled":
        kind = params.get("type")
        args = params.get("args")
        pieces: list[str] = []
        if isinstance(args, list):
            for arg in args[:8]:
                if not isinstance(arg, dict):
                    continue
                value = arg.get("value")
                description = arg.get("description")
                if isinstance(value, str):
                    pieces.append(value)
                elif isinstance(description, str):
                    pieces.append(description)
                elif value is not None:
                    pieces.append(json.dumps(value, default=str)[:120])
        text = " ".join(piece[:200] for piece in pieces)[:500]
        return CdpConsoleEntry(
            level=kind if isinstance(kind, str) else "log",
            text=text,
            origin="Runtime",
        )
    return None


def _navigation_identity(history: dict[str, Any]) -> tuple[str, str]:
    """Extract (title, url) from a ``Page.getNavigationHistory`` result."""
    entries = history.get("entries")
    index = history.get("index")
    if isinstance(entries, list) and entries:
        current = None
        if isinstance(index, int) and 0 <= index < len(entries):
            current = entries[index]
        if current is None:
            current = entries[-1]
        if isinstance(current, dict):
            title = current.get("title")
            url = current.get("url")
            return (
                title if isinstance(title, str) else "",
                url if isinstance(url, str) else "",
            )
    return "", ""


def inspect_page(
    ws_url: str,
    *,
    observe_ms: int = DEFAULT_OBSERVE_MS,
    max_console_entries: int = MAX_CONSOLE_ENTRIES,
    timeout_s: float = CONNECT_TIMEOUT_S,
) -> CdpInspect:
    """Passively inspect one page over its debugger WebSocket.

    Sends only read-only domain traffic: ``Page.enable``, ``Log.enable``,
    ``Runtime.enable``, ``Page.getNavigationHistory`` (title/url) and
    ``Page.getResourceTree`` (resource list), then listens for
    ``Log.entryAdded`` / ``Runtime.consoleAPICalled`` for ``observe_ms``.
    ``Runtime.evaluate`` is never sent -- nothing on the page is executed,
    requested, or intercepted. Raises :class:`CdpError` when the debugger
    URL is unusable or the setup round-trips fail; observation itself
    degrades gracefully (empty console on silence).
    """
    if observe_ms < 0 or observe_ms > MAX_OBSERVE_MS:
        raise CdpError(f"observe_ms must be between 0 and {MAX_OBSERVE_MS}")
    if max_console_entries < 1 or max_console_entries > MAX_CONSOLE_ENTRIES:
        raise CdpError(
            f"max_console_entries must be between 1 and {MAX_CONSOLE_ENTRIES}"
        )
    channel = _open_channel(ws_url, timeout_s)
    sink: list[CdpMessage] = []
    try:
        setup_deadline = channel.deadline(timeout_s + observe_ms / 1000.0)
        next_id = 0
        for domain in ("Page.enable", "Log.enable", "Runtime.enable"):
            next_id += 1
            _request(channel, next_id, domain, None, setup_deadline, sink)
        next_id += 1
        history = _request(
            channel, next_id, "Page.getNavigationHistory", None, setup_deadline, sink
        )
        title, url = _navigation_identity(history)
        next_id += 1
        tree = _request(
            channel, next_id, "Page.getResourceTree", None, setup_deadline, sink
        )
        resources, resources_truncated = _flatten_resources(tree.get("frameTree"))
        entries: list[CdpConsoleEntry] = []
        dropped = 0
        for message in sink:
            entry = _console_entry_from_event(message)
            if entry is not None:
                if len(entries) < max_console_entries:
                    entries.append(entry)
                else:
                    dropped += 1
        observe_deadline = channel.deadline(observe_ms / 1000.0)
        while len(entries) < max_console_entries:
            observed = channel.next_message(observe_deadline)
            if observed is None:
                break
            entry = _console_entry_from_event(observed)
            if entry is not None:
                entries.append(entry)
        evidence = Evidence(
            source="cdp.inspect",
            method="cdp_ws_passive",
            confidence=Confidence.HIGH,
            extra={
                "observe_ms": observe_ms,
                "domains": ["Page", "Log", "Runtime"],
                "evaluate_sent": False,
            },
        )
        return CdpInspect(
            title=title,
            url=url,
            resources=resources,
            resources_truncated=resources_truncated,
            console=tuple(entries),
            console_truncated=dropped > 0,
            observe_ms=observe_ms,
            evidence=evidence,
        )
    finally:
        channel.close()


def _png_dimensions(png: bytes) -> tuple[int | None, int | None]:
    """Parse width/height out of a PNG IHDR; (None, None) when not a PNG."""
    signature = b"\x89PNG\r\n\x1a\n"
    if len(png) < 24 or not png.startswith(signature):
        return None, None
    width = int.from_bytes(png[16:20], "big")
    height = int.from_bytes(png[20:24], "big")
    return width, height


def capture_screenshot(
    ws_url: str,
    out_path: Path,
    *,
    timeout_s: float = CONNECT_TIMEOUT_S,
) -> CdpScreenshot:
    """Capture one bounded PNG of the page via ``Page.captureScreenshot``.

    Read-only rendering query; the decoded payload is capped at
    :data:`MAX_SCREENSHOT_BYTES` before it is written to ``out_path``.
    Raises :class:`CdpError` when the debugger is unreachable, the capture
    fails, or the payload exceeds the cap (nothing is written in that case).
    """
    channel = _open_channel(ws_url, timeout_s)
    try:
        deadline = channel.deadline(timeout_s + 2.0)
        sink: list[CdpMessage] = []
        _request(channel, 1, "Page.enable", None, deadline, sink)
        result = _request(
            channel, 2, "Page.captureScreenshot", {"format": "png"}, deadline, sink
        )
        encoded = result.get("data")
        if not isinstance(encoded, str) or not encoded:
            raise CdpError("Page.captureScreenshot returned no data")
        try:
            png = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise CdpError(f"Page.captureScreenshot data is not base64: {exc}") from exc
        if len(png) > MAX_SCREENSHOT_BYTES:
            raise CdpError(
                f"screenshot payload {len(png)} bytes exceeds "
                f"{MAX_SCREENSHOT_BYTES}; nothing written"
            )
        width, height = _png_dimensions(png)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(png)
        except OSError as exc:
            raise CdpError(f"cannot write screenshot {out_path}: {exc}") from exc
        evidence = Evidence(
            source="cdp.inspect",
            method="page_capture_screenshot",
            confidence=Confidence.HIGH,
            extra={"bytes": len(png), "format": "png"},
        )
        return CdpScreenshot(
            path=str(out_path),
            byte_count=len(png),
            width=width,
            height=height,
            evidence=evidence,
        )
    finally:
        channel.close()


def webmcp_get_tools(
    ws_url: str,
    *,
    timeout_s: float = CONNECT_TIMEOUT_S,
) -> WebMcpProbe:
    """Probe the (optional) ``WebMCP`` domain on one target.

    Sends ``WebMCP.getAllTools`` -- a discovery query, not an execution --
    and tolerates every failure shape as a typed result: an unknown-domain
    ``-32601`` error, silence past the deadline, or an unreachable debugger
    all come back as ``available=False`` with a reason, never an exception.
    A real tool list is returned bounded at 100 entries.
    """
    try:
        channel = _open_channel(ws_url, timeout_s)
    except CdpError as exc:
        reason = f"debugger unreachable: {exc}"
        return WebMcpProbe(
            available=False,
            reason=reason,
            tools=(),
            evidence=_probe_evidence(reason, Confidence.LOW),
        )
    try:
        deadline = channel.deadline(timeout_s)
        try:
            result = _request(channel, 1, "WebMCP.getAllTools", {}, deadline, [])
        except CdpError as exc:
            reason = str(exc)
            if "-32601" in reason or "not found" in reason.lower():
                reason = "domain unavailable on this target"
            return WebMcpProbe(
                available=False,
                reason=reason,
                tools=(),
                evidence=_probe_evidence(reason, Confidence.LOW),
            )
        raw_tools = result.get("tools")
        if not isinstance(raw_tools, list):
            raw_tools = []
        tools: list[WebMcpTool] = []
        for item in raw_tools[:100]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            description = item.get("description")
            tools.append(
                WebMcpTool(
                    name=name,
                    description=description if isinstance(description, str) else None,
                )
            )
        return WebMcpProbe(
            available=True,
            reason=None,
            tools=tuple(tools),
            evidence=_probe_evidence("domain answered", Confidence.MEDIUM),
        )
    finally:
        channel.close()


def _probe_evidence(reason: str, confidence: Confidence) -> Evidence:
    """Evidence record for one WebMCP probe outcome."""
    return Evidence(
        source="cdp.inspect",
        method="webmcp_get_all_tools",
        confidence=confidence,
        extra={"reason": reason},
    )

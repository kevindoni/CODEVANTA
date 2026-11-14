"""MCP tools: ``codevanta_web_capture`` and ``codevanta_proto_decode``.

Two plain ``dict``-returning helpers like every other entry in
:mod:`codevanta.mcp_server.tools`, both fully offline. ``codevanta_web_capture``
summarises a HAR (HTTP Archive) capture: bounded per-entry rows, the
started-time span, a content-type histogram, unique hosts and per-entry gRPC
flags (content-type match or a valid 5-byte frame prefix).
``codevanta_proto_decode`` walks a protobuf wire-format body into a
structure-only field tree (MEDIUM confidence: field numbers are
semantic-free without a ``.proto`` schema), optionally stripping a gRPC
frame prefix first. Neither tool executes anything or touches the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.har_capture import load_har
from codevanta.analysis.proto_wire import decode_message, load_proto_bytes
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_proto_decode", "codevanta_web_capture"]


def _validate_capture_path(path: str) -> Path:
    """Return ``path`` as an existing regular file, or raise naming the problem."""
    if not isinstance(path, str):
        raise AnalysisError(f"path must be a string, got {type(path).__name__}")
    text = path.strip()
    if not text:
        raise AnalysisError("path must not be empty")
    candidate = Path(text).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def codevanta_web_capture(path: str) -> dict[str, Any]:
    """Summarise a HAR capture offline (bounded rows, honest totals).

    Returns ``entry_count``, ``total_time_ms``, the started-time span, a
    content-type histogram (max 16 keys), unique hosts (max 32), the first
    200 rows (method/url/status/time/content-type/grpc) and ``evidence``
    with ``source``/``method``/``confidence``. A file that is not a HAR
    document raises a typed error naming the defect.
    """
    target = _validate_capture_path(path)
    return load_har(target).to_dict()


def codevanta_proto_decode(path: str, grpc: bool = False) -> dict[str, Any]:
    """Decode a protobuf wire-format body into a structure-only field tree.

    With ``grpc``, a leading 5-byte gRPC frame prefix is stripped first and
    reported under ``grpc_frame``. Varints decode to ints, fixed fields to
    IEEE-754 floats, length-delimited payloads to nested fields when they
    parse cleanly and to bounded hex otherwise; warnings cover unknown wire
    types and truncated fields. Structure evidence only (MEDIUM
    confidence) -- meaning needs the ``.proto`` schema.
    """
    if not isinstance(grpc, bool):
        raise AnalysisError(f"grpc must be a boolean, got {type(grpc).__name__}")
    target = _validate_capture_path(path)
    data = load_proto_bytes(target)
    return decode_message(data, strip_grpc=grpc).to_dict()

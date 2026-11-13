"""MCP tools: ``codevanta_signal_sr``, ``codevanta_uart_decode``, ``codevanta_dtb``.

Three read-only windows onto the signal/firmware lane. Like every entry in
:mod:`codevanta.mcp_server.tools` these are plain ``dict``-returning
functions that raise the typed
:class:`~codevanta.core.report.AnalysisError` instead of tracebacks; none of
them launch a process (the sigrok-cli wrapper is deliberately not exposed
over MCP -- shelling out to external tools is a CLI concern).

* ``codevanta_signal_sr`` summarizes a sigrok ``.sr`` session archive
  (ZIP-bomb guarded, logic data stat'ed but never inflated).
* ``codevanta_uart_decode`` reads a raw logic-0/1 capture and runs the pure
  Python UART decoder-lite (medium confidence by design).
* ``codevanta_dtb`` parses a flattened devicetree blob (shallow walk,
  bounded properties).
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.fdt import parse_dtb_file
from codevanta.analysis.sigrok_sr import summarize_session
from codevanta.analysis.uart_decode import (
    DEFAULT_BAUD,
    DEFAULT_DATA_BITS,
    DEFAULT_PARITY,
    DEFAULT_STOP_BITS,
    decode_uart_file,
)
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_dtb", "codevanta_signal_sr", "codevanta_uart_decode"]


def _validate_path(path: Any) -> str:
    """Common MCP-path hygiene shared by all three tools."""
    if not isinstance(path, str) or not path.strip():
        raise AnalysisError("path must be a non-empty string")
    return path


def codevanta_signal_sr(path: str) -> dict[str, Any]:
    """Summarize one sigrok ``.sr`` session archive.

    Returns the JSON-safe ``SrSessionSummary`` payload: version, sample
    rate, device, channels, logic-file names and byte sizes, and the
    annotation count when the archive carries one.
    """
    target = _validate_path(path)
    return summarize_session(target).to_dict()


def codevanta_uart_decode(
    path: str,
    samplerate_hz: int,
    baud: int = DEFAULT_BAUD,
    databits: int = DEFAULT_DATA_BITS,
    parity: str = DEFAULT_PARITY,
    stopbits: int = DEFAULT_STOP_BITS,
) -> dict[str, Any]:
    """Decode a raw logic-0/1 capture file as UART (decoder-lite).

    The file holds one byte per sample: ``0`` is logic low, anything else is
    logic high. ``samplerate_hz`` must give at least 2 samples per baud bit;
    malformed parameters and missing files raise ``AnalysisError``. Garbage
    captures decode to few or zero bytes with warnings.
    """
    target = _validate_path(path)
    if not isinstance(samplerate_hz, int) or isinstance(samplerate_hz, bool):
        raise AnalysisError(f"samplerate_hz must be an integer, got {samplerate_hz!r}")
    return decode_uart_file(
        target,
        samplerate_hz=samplerate_hz,
        baud=baud,
        data_bits=databits,
        parity=parity,
        stop_bits=stopbits,
    ).to_dict()


def codevanta_dtb(path: str, node: str | None = None) -> dict[str, Any]:
    """Parse one flattened devicetree blob (shallow, bounded).

    ``node`` selects a top-level node whose properties are kept; ``None``
    keeps the root's own properties. Unknown node names are typed errors.
    """
    target = _validate_path(path)
    if node is not None and (not isinstance(node, str) or not node.strip()):
        raise AnalysisError("node must be a non-empty string or None")
    return parse_dtb_file(target, node=node).to_dict()

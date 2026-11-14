"""MCP tools: ``codevanta_bridges`` and the firmware/pcap depth bridges.

Three read-only tools cover the bridge lane:

* ``codevanta_bridges`` -- the capability report over a probe registry
  (binwalk, unblob, tshark, wabt, objdump, sigrok-cli, adb, gdb, z3); probes
  never raise, unavailability is a typed record with a reason.
* ``codevanta_firmware_extract`` -- binwalk/unblob extraction with a bounded
  timeout, bounded transcript parse and a shallow extraction-tree scan.
* ``codevanta_pcap_fields`` -- tshark ``-T fields`` extraction with a packet
  cap and a bounded row parse.

Like every entry in :mod:`codevanta.mcp_server.tools` these are plain
``dict``-returning functions; missing tools surface as the typed
:class:`~codevanta.core.report.AnalysisError` from the lane wrappers (with
install hints and the offline fallbacks) rather than a traceback. Note that
MCP registration also requires the matching ``@server.tool`` wrapper inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register (the v0.2.0 lesson).
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import binwalk_bridge, tshark_bridge
from codevanta.analysis.bridge import bridges_report
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_bridges", "codevanta_firmware_extract", "codevanta_pcap_fields"]


def codevanta_bridges() -> dict[str, Any]:
    """Probe every depth-bridge tool and return the capability report.

    Returns:
        A JSON-safe payload with the bounded ``bridges`` list (tool,
        available, version, reason), the total count and how many are
        available on this machine.

    Raises:
        AnalysisError: Only on internal probe failure (never for a missing
            tool -- absence is a capability record, not an error).
    """
    capabilities = bridges_report()
    return {
        "bridges": [capability.to_dict() for capability in capabilities],
        "count": len(capabilities),
        "available": sum(1 for capability in capabilities if capability.available),
    }


def codevanta_firmware_extract(
    path: str,
    out_dir: str,
    tool: str = "binwalk",
) -> dict[str, Any]:
    """Extract a firmware image with binwalk or unblob (bounded).

    Args:
        path: Firmware image to extract (read-only for CODEVANTA; the tool
            writes only under ``out_dir``).
        out_dir: Directory the extractor writes into (created when missing).
        tool: ``binwalk`` (default) or ``unblob``.

    Returns:
        The JSON-safe ``FirmwareExtractResult`` payload: bounded reported
        entries, shallow extraction-tree scan, warnings and evidence.

    Raises:
        AnalysisError: On an unknown tool, a missing file, an out-of-range
            timeout, or when the chosen tool is not on PATH -- the typed
            message names the install hint and the offline
            ``codevanta binmeta <file>`` magic-scan fallback.
    """
    if tool not in binwalk_bridge.EXTRACT_TOOLS:
        raise AnalysisError(
            f"tool must be one of {', '.join(binwalk_bridge.EXTRACT_TOOLS)}, got {tool!r}"
        )
    result = binwalk_bridge.firmware_extract(path, out_dir, tool=tool)
    return result.to_dict()


def codevanta_pcap_fields(
    path: str,
    fields: str,
    display_filter: str | None = None,
    packet_limit: int = tshark_bridge.DEFAULT_PACKET_LIMIT,
) -> dict[str, Any]:
    """Extract protocol fields from a pcap/pcapng capture with tshark.

    Args:
        path: Capture file (read-only; never executed).
        fields: Comma-separated tshark ``-e`` field names (max 16).
        display_filter: Optional tshark display filter (``-Y``) expression.
        packet_limit: Packets tshark decodes (``-c``), 1..100 (default 50).

    Returns:
        The JSON-safe ``PcapFieldsResult`` payload: bounded typed rows,
        warnings and evidence.

    Raises:
        AnalysisError: On a missing file, a malformed field name, an
            out-of-range packet limit, or when tshark is not on PATH -- the
            typed message names the install hint and the offline
            ``codevanta binmeta <file>`` structural pcap fallback.
    """
    result = tshark_bridge.pcap_fields(
        path,
        fields,
        display_filter=display_filter,
        packet_limit=packet_limit,
    )
    return result.to_dict()

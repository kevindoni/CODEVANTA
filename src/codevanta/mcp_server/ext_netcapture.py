"""MCP tools for network capture around a target command (no MCP imports).

Two tools: ``codevanta_net_interfaces`` (what ``tshark -D`` can capture on,
bounded and availability-gated) and ``codevanta_net_capture`` (run the
caller-selected command locally while a background ``tshark`` records this
machine's packets, then summarise the finished pcap offline through the
:mod:`codevanta.analysis.tshark_bridge` read path).

The lane is honest by construction:

* ``codevanta_net_capture`` EXECUTES the command you pass as an owned
  subprocess (dynamic analysis) AND records live network packets; both facts
  are stated in the tool description;
* live capture is privileged: it needs administrator rights and Npcap/WinPcap
  on Windows; without them tshark starts but records nothing. When tshark is
  missing entirely the tools return an honest unavailable object instead of an
  error, and the target command is NOT run;
* the capture is bounded: 1..60 seconds, at most 32 target arguments, a bounded
  join on the auto-stopped tshark process, and a stage-named warning for every
  degraded step (``tshark-start``, ``tshark-join``, ``pcap-missing``,
  ``summary``).

Both tools are stateless: unlike the proc lane there is no session registry --
each capture returns its full record once and the pcap file itself is the
artifact. The registration imports live in :mod:`codevanta.mcp_server.tools`;
the ``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codevanta.analysis.net_capture import capture_around, list_interfaces

TOOL_DESCRIPTION_NET_INTERFACES = (
    "List the network interfaces tshark can capture on (tshark -D), each as "
    "{number, device, description} and capped at 32 entries. HONESTY: live "
    "packet capture additionally requires administrator privileges and "
    "Npcap/WinPcap on Windows -- a listed interface does not guarantee packets "
    "can be recorded without them. When tshark is not on PATH the tool returns "
    "an honest unavailable object (available: false with the install hint) "
    "instead of an error."
)

TOOL_DESCRIPTION_NET_CAPTURE = (
    "Capture network traffic AROUND a target command: starts a background "
    "tshark on the chosen interface (auto-stop after capture_seconds, 1..60), "
    "runs the command you pass LOCALLY as an owned bounded subprocess "
    "concurrently, then waits for both (bounded join) and summarises the "
    "finished pcap offline (frame count and first packet fields) through the "
    "tshark bridge. SECURITY: this tool EXECUTES the command you pass and "
    "RECORDS this machine's network packets -- dynamic analysis, pass only "
    "commands you intend to run. HONESTY: live capture needs administrator "
    "privileges and Npcap/WinPcap on Windows; without them tshark may start "
    "yet record nothing and the warnings say so. When tshark is not on PATH "
    "nothing runs at all and an honest unavailable result is returned. "
    "Stage-named warnings (tshark-start, tshark-join, pcap-missing, summary) "
    "report every degraded step; the result carries the pcap path, size, "
    "sha256, the target's argv/exit code/streams and HIGH-confidence evidence "
    "(source net.capture, method tshark-around-run)."
)


def codevanta_net_interfaces() -> dict[str, Any]:
    """List the interfaces tshark can capture on, or an honest unavailable dict.

    Availability-gated through the bridge probe; the listing is bounded at 32
    entries. Never raises for a missing tshark.
    """
    return list_interfaces()


def codevanta_net_capture(
    command: str,
    arguments: Sequence[str] | None,
    capture_seconds: int,
    interface: str,
    output_directory: str | Path,
) -> dict[str, Any]:
    """Run the target while tshark records, then return the composed record.

    SECURITY: the command runs on this machine as an owned child process and
    the packets around it are recorded live. The composition goes through
    :func:`codevanta.analysis.net_capture.capture_around` (bounded: 1..60
    seconds, 32 arguments, bounded join); on success the pcap path, size,
    sha256, target summary, offline pcap summary and evidence come back as one
    JSON-safe dict. Caller mistakes are typed errors; a missing tshark is the
    honest unavailable result and runs nothing.
    """
    return capture_around(
        command,
        arguments,
        capture_seconds,
        interface,
        output_directory,
    ).to_dict()


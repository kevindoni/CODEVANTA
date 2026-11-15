"""MCP tool exposing the triage hashing engine (no MCP imports).

One tool: ``codevanta_triage`` (imphash per the Mandiant convention plus an
ssdeep-shaped fuzzy hash and a 0-100 similarity score, pure stdlib). The
registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import triage_hash


def codevanta_triage(path: str, compare: str | None = None) -> dict[str, Any]:
    """Compute triage hashes for one file, optionally scoring a second.

    Returns sha256, the imphash (MD5 over the lowercase dll.function import
    list, the VirusTotal-pivot convention; refused with a warning for
    ELF/Mach-O where this loader has no library pairing), and an
    ssdeep-shaped fuzzy signature (piecewise hashing, block ladder
    documented in docs/triage-hash.md). With ``compare`` set, adds a 0-100
    fuzzy similarity score between the two files. Nothing is executed.
    """
    report = triage_hash.triage_hashes(Path(path))
    payload = report.to_dict()
    if compare is not None:
        left = triage_hash.fuzzy_hash_file(Path(path)).signature
        right = triage_hash.fuzzy_hash_file(Path(compare)).signature
        payload["fuzzy_comparison"] = triage_hash.fuzzy_compare(left, right).to_dict()
    return payload

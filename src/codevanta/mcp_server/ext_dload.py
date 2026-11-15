"""MCP tool exposing the PE delay-load decoder (no MCP imports).

One tool: ``codevanta_delayload`` — pure-Python static decode of a PE's
``IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`` directory (data directory 13),
always available offline. The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives
inside :func:`codevanta.mcp_server.server.build_server` — imports alone
do not register anything.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis import delayload


def codevanta_delayload(path: str) -> dict[str, Any]:
    """Decode a PE file's delay-load import directory offline (pure Python).

    Walks the ``ImgDelayDescr`` array (v1 32-bit or v2 64-bit layout by
    directory size) and, per descriptor, reports the DLL name, the raw
    ``grAttrs`` with its named trait bits (``dlattrRva``, the CFG check
    bit), the IAT/INT RVAs and the bounded ``IMAGE_IMPORT_BY_NAME`` import
    list walked until NULL. Descriptors without ``dlattrRva`` carry
    bind-time addresses, which are treated as RVAs with an explicit
    warning. Absent directories report ``delay_load_present: false``;
    malformed structures raise typed errors. Nothing is executed.

    Raises:
        AnalysisError: When the path is missing, the file is not a PE,
            a descriptor array is truncated, or a DLL-name/INT/import-name
            RVA cannot be mapped to file bytes.
    """
    return delayload.inspect_delay_loads(path).to_dict()

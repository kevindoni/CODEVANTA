"""MCP tools exposing capability detection (no MCP imports).

Two tools: ``codevanta_capabilities`` (pure-Python, file-scope capability
detection over imports/strings/exports/sections, always available offline)
and ``codevanta_capability_profile`` (the eight fixed capability domains
-- network, crypto, file_system, process, registry, service, gui,
dynamic_loading -- scanned from raw bytes with a deterministic risk score).
The registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import capabilities


def codevanta_capabilities(
    path: str,
    extra_rules: str | None = None,
    string_limit: int = 5000,
) -> dict[str, Any]:
    """Detect file-scope capabilities in a binary via bounded rule matching.

    Evaluates the built-in rule pack (plus optional JSON extra rules) against
    the binary's imports, strings, exports and section names: HTTP/TCP
    communication, process creation, registry writes, service installs,
    keylogging, screenshots, reverse-shell and injection candidates, packing
    hints and more. Every match lists exactly which features fired and where
    (import table entries, string offsets) -- the feature evidence is
    certain, the capability conclusion is medium confidence. File scope
    only: no function-level attribution, unlike full capa.
    """
    return capabilities.detect_capabilities(
        Path(path),
        extra_rules=Path(extra_rules) if extra_rules else None,
        string_limit=string_limit,
    ).to_dict()


def codevanta_capability_profile(path: str) -> dict[str, Any]:
    """Profile a binary against the eight fixed capability domains.

    Scans the raw bytes for fixed marker sets (socket/winsock/curl/reqwest,
    bcrypt/crypt32/aes/rsa/sha, fopen/CreateFile/read/write,
    CreateProcess/exec/ptrace, RegOpenKey/RegQueryValue,
    OpenSCManager/StartService, CreateWindow/user32/cairo,
    dlopen/GetProcAddress/lazy_static) and reports per domain
    ``{name, detected, evidence_strings (<=8), confidence}`` plus a
    deterministic 0-100 ``overall_risk_score`` over dangerous domain
    combinations and a bounded report-level evidence list (<=16). The
    markers are certain; the capability conclusion is medium confidence.
    Nothing is executed.
    """
    return capabilities.profile_capabilities(Path(path)).to_dict()

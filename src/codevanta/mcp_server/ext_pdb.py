"""MCP tool exposing the PDB information parser (no MCP imports).

One tool: ``codevanta_pdb`` (pure-stdlib MSF v7 walk of a local .pdb, or the
CodeView debug reference of a PE). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import pdb_info


def codevanta_pdb(
    path: str, max_streams: int = 256, max_modules: int = 4096
) -> dict[str, Any]:
    """Read PDB information offline: MSF structure, or a PE's CodeView record.

    A ``.pdb`` input gets the bounded MSF v7 walk (streams, info stream
    GUID/age/version, named streams, DBI module list); any other input is
    treated as a PE and returns its debug directory's CodeView record -- the
    PDB path, GUID and age that identify the symbol file. No symbol records,
    no type info (TPI/IPI), no download, no network, ever. Nothing is
    executed.
    """
    candidate = Path(path)
    if candidate.suffix.lower() == ".pdb" or _starts_with_msf_magic(candidate):
        return _pdb_payload(candidate, max_streams, max_modules)
    reference = pdb_info.codeview_reference(candidate)
    payload: dict[str, Any] = reference.to_dict() if reference is not None else {
        "mode": "codeview",
        "codeview": None,
        "detail": "no CodeView debug record in this binary",
        "evidence": {
            "source": "pdb.info",
            "method": "pe_debug_directory",
            "confidence": "certain",
        },
    }
    payload["mode"] = "codeview"
    return payload


def _pdb_payload(path: Path, max_streams: int, max_modules: int) -> dict[str, Any]:
    """Full MSF walk payload for a .pdb input."""
    payload = pdb_info.parse_pdb(path, max_streams=max_streams, max_modules=max_modules).to_dict()
    payload["mode"] = "pdb"
    return payload


def _starts_with_msf_magic(path: Path) -> bool:
    """True when the file begins with the MSF superblock magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(len(pdb_info.MSF_MAGIC)) == pdb_info.MSF_MAGIC
    except OSError:
        return False

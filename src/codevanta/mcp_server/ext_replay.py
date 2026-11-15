"""MCP tool exposing the HAR replay-fixture engine (no MCP imports).

One tool: ``codevanta_replay_fixture`` (pure-Python, offline normalization
of a recorded HAR into a deterministic replay fixture document). The
registration import lives in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import replay_fixture


def codevanta_replay_fixture(
    har_path: str,
    max_entries: int = replay_fixture.DEFAULT_MAX_ENTRIES,
    max_body_bytes: int = replay_fixture.DEFAULT_MAX_BODY_BYTES,
) -> dict[str, Any]:
    """Normalize a HAR recording into a bounded replay fixture.

    Entries become deterministic request/response records (bodies as size +
    sha256 + a 128-byte preview only, never inlined) and the endpoint
    manifest collapses paths into templates (``/api/items/42`` ->
    ``/api/items/{n}``) -- the surface an agent could train or test against.
    Nothing is served or executed; this is the offline half of a replay
    environment, not a server.
    """
    return replay_fixture.build_replay_fixture(
        Path(har_path), max_entries=max_entries, max_body_bytes=max_body_bytes
    ).to_dict()

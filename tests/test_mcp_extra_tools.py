"""MCP tool tests for the container inspector and PNG differ (extra tools).

Both tools are thin wrappers over analysis modules that carry their own deep
test suites, so these cases cover the wrapper contract only: the typed
``AnalysisError`` surfaces through the plain-function layer and the
empty/undetected file stays a valid result, never an error.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools


def test_mcp_containers_tool(tmp_path: Path) -> None:
    # Missing file: typed error, not FileNotFoundError.
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_containers(str(tmp_path / "ghost.bin"))
    # A file matching no container format is a valid empty detection.
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    payload = tools.codevanta_containers(str(empty))
    assert payload["path"] == str(empty)
    assert payload["size_bytes"] == 0
    assert payload["detected"] == []


def test_mcp_png_diff_tool(tmp_path: Path) -> None:
    # Bad signature: typed "png:" error, not a raw decode crash.
    garbage = tmp_path / "garbage.png"
    garbage.write_bytes(b"\x89PNG\r\n\x1a\n" + b"broken")
    with pytest.raises(AnalysisError, match="png:"):
        tools.codevanta_png_diff(str(garbage), str(garbage))

"""MCP tool for the lane-codegen starter-code generator (no MCP imports).

One tool: ``codevanta_rebuild_generate`` -- read a studied rebuild project
(craft.json + capture/ evidence written by ``codevanta_rebuild``) and
deterministically write starter implementation files into
``output_directory``: ``app/main.py`` with import-surfaced stubs per observed
API group, ``app/pseudo_c/*.c`` evidence files when deep-mode decompiles were
recorded, ``ui_layout.json`` + ``ui.html`` from the dialog-decode capture when
present, and ``checks/behavior_checklist.md``. The registration import lives
in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives
inside :func:`codevanta.mcp_server.server.build_server` -- imports alone do
not register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.rebuild_codegen import generate_starter

__all__ = [
    "TOOL_DESCRIPTION_CODEGEN",
    "codevanta_rebuild_generate",
]

TOOL_DESCRIPTION_CODEGEN = (
    "Generate deterministic starter implementation code from a studied "
    "rebuild project (the craft.json + capture/ layout written by "
    "codevanta_rebuild). Writes into output_directory: app/main.py with a "
    "header citing the target and the sha256 evidence digest, one "
    "import-surface block per observed API group (kernel32/ws2_32/user32 ... "
    "grouped from the capture's imports evidence) and one "
    "raise-NotImplementedError stub per group citing the reference count and "
    "an example symbol, the deep-mode pseudo-C evidence as app/pseudo_c/*.c "
    "when recorded, ui_layout.json plus a deterministic ui.html preview from "
    "the dialog-decode capture when present, and checks/behavior_checklist.md "
    "with one item per recorded check. Identical inputs produce byte-identical "
    "files (no timestamps); work is bounded (32 files, 256 stubs, 2000 "
    "lines/file) with honest truncation warnings. Nothing is executed and "
    "nothing touches the network."
)


def codevanta_rebuild_generate(
    project_dir: str,
    output_directory: str,
    language: str = "python",
) -> dict[str, Any]:
    """Write starter files for a studied rebuild project into output_directory."""
    manifest = generate_starter(Path(project_dir), Path(output_directory), language=language)  # type: ignore[arg-type]
    return manifest.to_dict()

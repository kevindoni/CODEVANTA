"""MCP tools for the fs lane (no MCP imports).

Two tools: ``codevanta_fs_snapshot`` (recursive bounded directory-tree
manifest written as ``fs_snapshot.json``) and ``codevanta_fs_diff`` (compare
two snapshot files into created/deleted/modified lists with a verdict). The
registration imports live in :mod:`codevanta.mcp_server.tools`; the
``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from codevanta.analysis import fs_diff
from codevanta.core.report import AnalysisError

SNAPSHOT_FILENAME = "fs_snapshot.json"

TOOL_DESCRIPTION_FS_SNAPSHOT = (
    "Snapshot a directory tree recursively, fully offline and pure Python: "
    "os.walk (symlinks never followed) records every regular file with its "
    "relative POSIX path, size and sha256 (files above 8 MiB are recorded "
    "size-only with hashed=false), every directory, and every symlink with "
    "its clipped target text. Bounded at 2048 entries and 256 MiB of hashed "
    "bytes; overflow is an honest truncated flag plus warnings, never a "
    "crash. No timestamps are recorded, so the same tree snapshots to a "
    "byte-identical manifest. The manifest is written as fs_snapshot.json "
    "into <output_directory> and returned together with the written file's "
    "path, byte count and sha256. Missing roots and non-directory roots are "
    "typed errors. Nothing is executed."
)

TOOL_DESCRIPTION_FS_DIFF = (
    "Diff two filesystem snapshot files (as produced by codevanta_fs_snapshot) "
    "and classify every relative path: created (after only), deleted (before "
    "only), modified (both sides, fingerprint differs -- content sha256 when "
    "both sides hashed it, size fallback flagged size_only) and unchanged "
    "(counted only). The verdict is identical when nothing changed, otherwise "
    "changed. Every list is bounded (512 entries) with per-list truncation "
    "flags while counts report the true totals. Missing, unreadable or "
    "malformed snapshot files are typed errors. Pure stdlib; nothing is "
    "executed."
)


def codevanta_fs_snapshot(root: str, output_directory: str) -> dict[str, Any]:
    """Snapshot the tree at ``root`` and write ``fs_snapshot.json``.

    Returns the manifest dict augmented with a ``written`` section carrying
    the artifact path, byte count and sha256.
    """
    manifest = fs_diff.snapshot_tree(Path(root)).to_dict()
    out_dir = Path(output_directory).expanduser()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AnalysisError(
            f"cannot create output directory {str(output_directory)!r}: {exc}"
        ) from exc
    target = out_dir / SNAPSHOT_FILENAME
    try:
        data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        target.write_bytes(data)
    except OSError as exc:
        raise AnalysisError(
            f"cannot write snapshot to {str(target)!r}: {exc}"
        ) from exc
    manifest["written"] = {
        "path": str(target),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return manifest


def codevanta_fs_diff(before: str, after: str) -> dict[str, Any]:
    """Load two snapshot JSON files and return the bounded diff dict."""
    return fs_diff.diff_snapshots(
        fs_diff.load_snapshot(before),
        fs_diff.load_snapshot(after),
    ).to_dict()

"""MCP tools: ``codevanta_binmeta`` and ``codevanta_sqlite``.

Two plain ``dict``-returning helpers like every other entry in
:mod:`codevanta.mcp_server.tools`, so the server layer can publish them the
same way it publishes the core tools. ``codevanta_binmeta`` auto-detects the
container families the binary lane parses (WASM, EVM, GGUF, safetensors,
pcap/pcapng, firmware magics); ``codevanta_sqlite`` introspects a SQLite
database strictly read-only through the ``mode=ro&immutable=1`` URI and never
writes anything. Neither tool launches anything, and every failure surfaces
as :class:`~codevanta.core.report.AnalysisError` rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis.containers import inspect_container
from codevanta.analysis.sqlite_view import inspect_sqlite
from codevanta.core.report import AnalysisError

__all__ = ["codevanta_binmeta", "codevanta_sqlite"]


def _validate_container_path(path: str) -> Path:
    """Return ``path`` as an existing regular file, or raise naming the problem."""
    if not isinstance(path, str):
        raise AnalysisError(f"path must be a string, got {type(path).__name__}")
    text = path.strip()
    if not text:
        raise AnalysisError("path must not be empty")
    candidate = Path(text).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    return candidate


def codevanta_binmeta(path: str) -> dict[str, Any]:
    """Auto-detect container formats in ``path`` and return a bounded summary.

    Runs the WASM, GGUF, safetensors, pcap/pcapng, EVM and firmware magic
    inspectors over one read of the file. Detection is magic-gated except for
    EVM, whose verdict is a labelled heuristic (``evm_like``); every summary
    carries ``evidence`` with ``source``/``method``/``confidence``.
    """
    return inspect_container(_validate_container_path(path)).to_dict()


def codevanta_sqlite(path: str, table: str | None = None) -> dict[str, Any]:
    """Introspect a SQLite database read-only; ``table`` adds schema + samples.

    The connection is opened through ``file:...?mode=ro&immutable=1``, so the
    tool cannot write, cannot create journals and never replays a WAL (a
    present ``-wal`` file is reported as ignored). Tables are bounded at 32
    with row counts; a requested table adds its columns and up to 10 sample
    rows with JSON-safe values.
    """
    if table is not None and not isinstance(table, str):
        raise AnalysisError(f"table must be a string, got {type(table).__name__}")
    return inspect_sqlite(
        _validate_container_path(path), None if table is None else table.strip() or None
    ).to_dict()

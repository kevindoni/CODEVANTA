"""MCP tool exposing the rebuild engine (no MCP imports).

One tool family: ``codevanta_rebuild`` (start a Study → Build → Check → Ready
project), plus ``codevanta_rebuild_list``, ``codevanta_rebuild_show`` and
``codevanta_rebuild_check``. The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from codevanta.cli.rebuild import _attempt_auto_build as attempt_auto_build
from codevanta.cli.rebuild import _mark_ready as mark_ready
from codevanta.cli.rebuild import _start_build as start_build
from codevanta.cli.rebuild import (
    _suggest_stack,
    build_project,
    check_behavior,
    check_build,
    get_project,
    list_projects,
)
from codevanta.core.report import AnalysisError

__all__ = [
    "codevanta_rebuild",
    "codevanta_rebuild_build",
    "codevanta_rebuild_build_auto",
    "codevanta_rebuild_check",
    "codevanta_rebuild_check_behavior",
    "codevanta_rebuild_improve",
    "codevanta_rebuild_list",
    "codevanta_rebuild_ready",
    "codevanta_rebuild_show",
]


def _default_root() -> Path:
    configured = os.environ.get("CODEVANTA_REBUILD_ROOT")
    if configured and configured.strip():
        return Path(configured)
    return Path.home() / ".codevanta" / "rebuilds"


def codevanta_rebuild(
    target: str,
    request: str,
    mode: str = "clean-room",
    root: str | None = None,
) -> dict[str, Any]:
    """Start a rebuild project: study the target and scaffold the directory.

    Study → Build → Check → Ready. This command runs the Study step: it
    inspects the target with CODEVANTA's analysis engine (surface-only in
    clean-room mode, all tools in deep mode), writes ``craft.json`` and the
    capture, and returns the project id. An external coding agent then builds
    the recreation in ``app/``; use ``codevanta_rebuild_check`` to compare it
    against the original.

    Nothing is executed and nothing touches the network.
    """
    if mode not in ("clean-room", "deep"):
        raise AnalysisError("mode must be 'clean-room' or 'deep'")
    root_path = Path(root) if root else _default_root()
    record = build_project(target, request, mode=mode, root=root_path)
    project_dir = root_path / record.id
    return {
        "id": record.id,
        "name": record.name,
        "target": record.target,
        "request": record.request,
        "mode": record.mode,
        "status": record.status,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "directory": str(project_dir),
        "study_entries": record.study_entries,
        "inbox": record.inbox,
    }


def codevanta_rebuild_list(root: str | None = None) -> dict[str, Any]:
    """List rebuild projects, most recently updated first."""
    root_path = Path(root) if root else _default_root()
    records = list_projects(root_path)
    return {
        "count": len(records),
        "projects": [
            {
                "id": r.id,
                "name": r.name,
                "status": r.status,
                "mode": r.mode,
                "target": r.target,
                "updated_at": r.updated_at,
            }
            for r in records
        ],
    }


def codevanta_rebuild_show(project_id: str, root: str | None = None) -> dict[str, Any]:
    """Show one project's full record: request, status, study, checks, inbox."""
    root_path = Path(root) if root else _default_root()
    record = get_project(project_id, root_path)
    if record is None:
        raise AnalysisError(f"project {project_id!r} not found")
    return {
        "id": record.id,
        "name": record.name,
        "target": record.target,
        "request": record.request,
        "mode": record.mode,
        "status": record.status,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "study_entries": record.study_entries,
        "checks": record.checks,
        "inbox": record.inbox,
    }


def codevanta_rebuild_check(
    project_id: str,
    build_path: str,
    root: str | None = None,
) -> dict[str, Any]:
    """Compare a build against the project's original target and record the check.

    Returns the check payload including whether the build is identical to the
    original (for binary targets, via CODEVANTA's structural comparison;
    otherwise via SHA-256 + size).
    """
    root_path = Path(root) if root else _default_root()
    return check_build(project_id, Path(build_path), root=root_path)


def codevanta_rebuild_check_behavior(
    project_id: str,
    build_path: str,
    run_original: bool = False,
    timeout: int = 10,
    root: str | None = None,
) -> dict[str, Any]:
    """Compare how the build RUNS against how the original runs.

    Runs the built artifact, captures exit code and stdout/stderr, and — only
    when ``run_original`` is true (explicit consent; this executes the
    original binary on the machine) — runs the original target and reports
    exit-code match plus stdout similarity. The check is recorded under the
    project's ``checks/`` directory with kind ``behavior``.
    """
    root_path = Path(root) if root else _default_root()
    return check_behavior(
        project_id,
        Path(build_path),
        root=root_path,
        run_original=run_original,
        timeout=timeout,
    )


def codevanta_rebuild_ready(
    project_id: str,
    root: str | None = None,
) -> dict[str, Any]:
    """Mark a rebuild project as ``ready``.

    Requires the project to be in ``checked`` status and the most recent
    check to report ``identical: true``. Returns the updated project record.
    """
    root_path = Path(root) if root else _default_root()
    record = mark_ready(project_id, root=root_path)
    return {
        "id": record.id,
        "name": record.name,
        "status": record.status,
        "updated_at": record.updated_at,
    }


def codevanta_rebuild_build(
    project_id: str,
    root: str | None = None,
) -> dict[str, Any]:
    """Mark a rebuild project as ``building`` and scaffold the ``app/``
    directory. Returns the updated project record and the list of files
    written for the coding agent to fill in.
    """
    root_path = Path(root) if root else _default_root()
    record, written = start_build(project_id, root=root_path)
    return {
        "id": record.id,
        "name": record.name,
        "status": record.status,
        "stack": _suggest_stack(record.study_entries),
        "directory": str(root_path / record.id / "app"),
        "files": [str(p.relative_to(root_path / record.id)) for p in written],
    }


def codevanta_rebuild_build_auto(
    project_id: str,
    root: str | None = None,
    max_attempts: int = 5,
) -> dict[str, Any]:
    """Run the automated Build → Check → Improve loop.

    Generates code from study entries, writes it to ``app/``, runs
    ``codevanta_rebuild_check``, and repeats until identical or
    ``max_attempts`` is reached. Marks the project ``ready`` on success.
    Returns a summary with status, attempts used, and the last check result.
    """
    root_path = Path(root) if root else _default_root()
    return attempt_auto_build(project_id, root=root_path, max_attempts=max_attempts)


def codevanta_rebuild_improve(
    project_id: str,
    hint: str | None = None,
    root: str | None = None,
) -> dict[str, Any]:
    """Request an improvement pass for a rebuild project.

    Regenerates the code in ``app/`` using the latest study entries (plus an
    optional hint), then runs a check. Returns whether the build is now
    identical. Intended for external coding agents to iterate toward Ready.
    """
    root_path = Path(root) if root else _default_root()
    summary = attempt_auto_build(project_id, root=root_path, max_attempts=1)
    return {
        "id": project_id,
        "status": summary["status"],
        "identical": summary["identical"],
        "attempts": summary["attempts"],
        "last_check": summary["last_check"],
    }

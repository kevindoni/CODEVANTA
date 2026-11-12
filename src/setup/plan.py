"""Setup plan model: describe every change before writing anything."""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ACTION_CREATE = "create"
ACTION_UPDATE = "update"
ACTION_NOOP = "noop"


@dataclass(frozen=True)
class FileChange:
    """One configuration file change inside a setup plan."""

    path: Path
    action: str
    previous_content: str
    new_content: str
    diff: str

    @property
    def will_write(self) -> bool:
        return self.action in (ACTION_CREATE, ACTION_UPDATE)

    def to_dict(self) -> dict[str, Any]:
        return {"path": str(self.path), "action": self.action, "diff": self.diff}


@dataclass(frozen=True)
class SetupPlan:
    """The complete set of changes for one client and scope."""

    client: str
    scope: str
    changes: tuple[FileChange, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_changes(self) -> bool:
        return any(change.will_write for change in self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "client": self.client,
            "scope": self.scope,
            "has_changes": self.has_changes,
            "changes": [change.to_dict() for change in self.changes],
            "notes": list(self.notes),
        }


def build_diff(path: Path, previous: str, new: str) -> str:
    """Return a unified diff between ``previous`` and ``new``."""
    return "".join(
        difflib.unified_diff(
            previous.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
        )
    )


def make_change(path: Path, previous: str, new: str) -> FileChange:
    """Classify a change as create, update, or noop and attach its diff."""
    if previous == new:
        return FileChange(path=path, action=ACTION_NOOP, previous_content=previous, new_content=new, diff="")
    action = ACTION_UPDATE if previous else ACTION_CREATE
    return FileChange(
        path=path,
        action=action,
        previous_content=previous,
        new_content=new,
        diff=build_diff(path, previous, new),
    )

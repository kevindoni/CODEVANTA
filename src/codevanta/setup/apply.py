"""Apply setup plans safely (backups, idempotent writes)."""

from __future__ import annotations

from pathlib import Path

from .plan import SetupPlan


def apply_plan(plan: SetupPlan) -> list[Path]:
    """Write every file in ``plan`` that actually changes, with a backup."""
    written: list[Path] = []
    for change in plan.changes:
        if not change.will_write:
            continue
        change.path.parent.mkdir(parents=True, exist_ok=True)
        if change.path.exists():
            backup = change.path.with_name(change.path.name + ".codevanta.bak")
            backup.write_text(change.previous_content, encoding="utf-8")
        change.path.write_text(change.new_content, encoding="utf-8")
        written.append(change.path)
    return written

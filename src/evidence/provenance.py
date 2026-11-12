"""Provenance tracking for analysis runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Provenance:
    """Records how a report or finding was produced."""

    tool: str = "codevanta"
    tool_version: str = "0.1.0"
    created_at: str = field(default_factory=utc_now_iso)
    steps: list[str] = field(default_factory=list)

    def add_step(self, step: str) -> Provenance:
        """Append a processing step and return ``self`` for chaining."""
        if not step:
            raise ValueError("step must not be empty")
        self.steps.append(step)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "created_at": self.created_at,
            "steps": list(self.steps),
        }

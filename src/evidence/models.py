"""Evidence records that justify every analysis finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .confidence import Confidence


@dataclass(frozen=True)
class Evidence:
    """A traceable justification for a single analysis finding.

    Attributes:
        source: Where the finding came from, e.g. ``"pe.export_table"``.
        method: How it was obtained, e.g. ``"export_directory"``.
        confidence: How reliable the finding is.
        address: Optional virtual address the evidence refers to.
        detail: Optional human-readable note.
        extra: Optional structured metadata for the report.
    """

    source: str
    method: str
    confidence: Confidence = Confidence.UNKNOWN
    address: int | None = None
    detail: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source": self.source,
            "method": self.method,
            "confidence": self.confidence.value,
        }
        if self.address is not None:
            data["address"] = f"0x{self.address:x}"
        if self.detail:
            data["detail"] = self.detail
        if self.extra:
            data["extra"] = dict(self.extra)
        return data

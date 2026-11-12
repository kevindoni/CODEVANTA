"""Confidence levels for analysis findings.

The engine never presents a guess as a certainty. Every finding carries one of
these levels and, where useful, the numeric ``score`` for ordering.
"""

from __future__ import annotations

from enum import Enum


class Confidence(str, Enum):
    """How strongly a finding is supported by evidence."""

    CERTAIN = "certain"  # direct, unambiguous data from the file format
    HIGH = "high"        # strong structural evidence (e.g. export table)
    MEDIUM = "medium"    # indirect evidence (e.g. entry point)
    LOW = "low"          # weak or inferred evidence
    UNKNOWN = "unknown"  # no confidence can be established

    def __str__(self) -> str:
        return self.value

    @property
    def score(self) -> float:
        """Normalized weight in [0.0, 1.0] used for ordering and merging."""
        return _SCORES[self]


_SCORES: dict[Confidence, float] = {
    Confidence.CERTAIN: 1.0,
    Confidence.HIGH: 0.8,
    Confidence.MEDIUM: 0.5,
    Confidence.LOW: 0.2,
    Confidence.UNKNOWN: 0.0,
}

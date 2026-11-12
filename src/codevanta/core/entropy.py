"""Per-section Shannon entropy for packing triage.

Entropy itself is a plain measurement over file bytes (confidence ``certain``);
the *packed/compressed* interpretation is a heuristic and is labelled as such
(``medium`` confidence, threshold stated in the evidence detail). Sections
without file bytes (e.g. ``S_ZEROFILL``) are reported with ``entropy=None``
rather than a fabricated value. Sampling is capped per section because entropy
converges quickly; the sample size actually used is part of every result.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError, read_code
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_SAMPLE_BYTES",
    "DEFAULT_MIN_SAMPLE_BYTES",
    "PACKED_HINT_THRESHOLD",
    "EntropyReport",
    "SectionEntropy",
    "analyze_entropy",
]

#: Entropy (bits/byte) at or above which a section is flagged as possibly
#: packed or compressed. 7.2 is a widely used rule of thumb, not a law.
PACKED_HINT_THRESHOLD = 7.2

#: Default cap on bytes read per section; entropy converges well before this.
DEFAULT_MAX_SAMPLE_BYTES = 65_536

#: Below this sample size the entropy is still reported but too noisy to mean
#: much, so the packed hint is suppressed and a caveat is attached instead.
DEFAULT_MIN_SAMPLE_BYTES = 256

#: Hard ceiling accepted for ``max_sample_bytes`` (bounded-resource rule).
MAX_SAMPLE_LIMIT = 4 * 1024 * 1024

_MAX_ENTROPY = 8.0


@dataclass(frozen=True)
class SectionEntropy:
    """Entropy of one section, sampled from its file bytes."""

    name: str
    virtual_address: int
    size: int
    entropy: float | None
    sampled_bytes: int
    is_executable: bool
    packed_hint: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:x}",
            "size": self.size,
            "entropy": round(self.entropy, 4) if self.entropy is not None else None,
            "sampled_bytes": self.sampled_bytes,
            "executable": self.is_executable,
            "packed_hint": self.packed_hint,
            "evidence": self.evidence.to_dict(),
        }
        return data


@dataclass(frozen=True)
class EntropyReport:
    """Entropy triage across every section of one binary."""

    sections: list[SectionEntropy]
    threshold: float
    warnings: tuple[str, ...]
    evidence: Evidence

    @property
    def packed_candidates(self) -> list[SectionEntropy]:
        """Sections whose entropy reached the packed-compression threshold."""
        return [section for section in self.sections if section.packed_hint]

    def to_dict(self) -> dict[str, Any]:
        packed = self.packed_candidates
        return {
            "section_count": len(self.sections),
            "threshold": self.threshold,
            "packed_candidate_count": len(packed),
            "packed_candidates": [section.name for section in packed],
            "sections": [section.to_dict() for section in self.sections],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return min(entropy, _MAX_ENTROPY)


def analyze_entropy(
    path: str | Path,
    info: BinaryInfo,
    *,
    threshold: float = PACKED_HINT_THRESHOLD,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
    min_sample_bytes: int = DEFAULT_MIN_SAMPLE_BYTES,
) -> EntropyReport:
    """Compute per-section entropy and flag possible packing.

    Args:
        path: File the metadata in ``info`` was loaded from (read-only).
        info: Normalized binary metadata.
        threshold: Entropy at or above which ``packed_hint`` is set (0 < t <= 8).
        max_sample_bytes: Bytes read per section at most (1 .. 4 MiB).
        min_sample_bytes: Sample size below which the packed hint is suppressed.

    Returns:
        An :class:`EntropyReport` with one entry per section, sorted by
        entropy (descending), sections without file bytes carrying ``None``.

    Raises:
        AnalysisError: If any limit is out of range.
    """
    if not 0.0 < threshold <= _MAX_ENTROPY:
        raise AnalysisError(f"threshold must be in (0, {_MAX_ENTROPY}]")
    if max_sample_bytes < 1:
        raise AnalysisError("max_sample_bytes must be >= 1")
    if max_sample_bytes > MAX_SAMPLE_LIMIT:
        raise AnalysisError(f"max_sample_bytes too large (limit {MAX_SAMPLE_LIMIT})")
    if min_sample_bytes < 1:
        raise AnalysisError("min_sample_bytes must be >= 1")

    warnings: list[str] = []
    results: list[SectionEntropy] = []
    for section in info.sections:
        entropy: float | None = None
        sampled = 0
        # File-backed means: PE/Mach-O raw bytes, or an ELF section with a real
        # file offset (ELF loader metadata carries raw_size=0 by design).
        if section.raw_size > 0 or section.offset > 0:
            try:
                data = read_code(path, info, section.virtual_address, max_sample_bytes)
            except (AnalysisError, OSError) as exc:
                warnings.append(
                    f"section {section.name!r}: cannot read bytes ({exc}); entropy unknown"
                )
            else:
                sampled = len(data)
                if sampled:
                    entropy = shannon_entropy(data)
                else:
                    warnings.append(
                        f"section {section.name!r}: no file bytes; entropy unknown"
                    )
        else:
            warnings.append(
                f"section {section.name!r}: not file-backed (size {section.size}); "
                "entropy unknown"
            )

        packed_hint = entropy is not None and entropy >= threshold
        detail_suffix = ""
        if entropy is None:
            detail = "entropy not computable: no file bytes"
            confidence = Confidence.LOW
        else:
            confidence = Confidence.CERTAIN
            if sampled < min_sample_bytes:
                packed_hint = False
                detail_suffix = "; sample too small for a packing judgment"
                detail = (
                    f"entropy {entropy:.3f} bits/byte from {sampled} sampled byte(s)"
                    + detail_suffix
                )
            else:
                detail = (
                    f"entropy {entropy:.3f} bits/byte from {sampled} sampled byte(s); "
                    f"packed hint at >={threshold} is a heuristic, not proof"
                    if packed_hint
                    else f"entropy {entropy:.3f} bits/byte from {sampled} sampled byte(s)"
                )
        results.append(
            SectionEntropy(
                name=section.name,
                virtual_address=section.virtual_address,
                size=section.size,
                entropy=entropy,
                sampled_bytes=sampled,
                is_executable=section.is_executable,
                packed_hint=packed_hint,
                evidence=Evidence(
                    source="entropy.section",
                    method="shannon_entropy",
                    confidence=confidence,
                    address=section.virtual_address,
                    detail=detail,
                ),
            )
        )

    results.sort(key=lambda item: (-1 if item.entropy is None else -item.entropy, item.name))
    packed_names = [item.name for item in results if item.packed_hint]
    report_evidence = Evidence(
        source="entropy.triage",
        method="per_section_shannon_entropy",
        confidence=Confidence.CERTAIN,
        detail=(
            f"{len(results)} section(s) measured; threshold {threshold}; "
            f"{len(packed_names)} packed candidate(s)"
            + (f" ({', '.join(packed_names)})" if packed_names else "")
        ),
    )
    return EntropyReport(
        sections=results,
        threshold=threshold,
        warnings=tuple(warnings),
        evidence=report_evidence,
    )

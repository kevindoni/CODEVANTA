"""Structural diffing of two loaded binaries.

:func:`diff_infos` compares two :class:`~codevanta.core.loader.BinaryInfo`
snapshots together with their discovered function candidates and reports what
was added, removed or changed. :func:`diff_binaries` is the convenience entry
point that loads both files first.

The comparison is deliberately *structural* by default: it only reads metadata
the loader already extracted (sections, imports, exports) plus the candidate list
produced by :func:`~codevanta.core.functions.discover_functions`. No target file
is executed and no instruction bytes are compared, so a ``changed`` entry means
"the observed metadata differs", never "the machine code differs". Every delta
carries that caveat in its evidence record at ``Confidence.MEDIUM``.

``deep=True`` adds a *content* signal on top of that metadata, without changing
any structural rule. For every function that matches by address, the normalized
instruction stream of both sides is fingerprinted with
:func:`~codevanta.analysis.function_hash.function_fingerprint`; when the digests
differ the entry becomes ``changed`` (with both digests and a content note), and
when they match although the metadata changed, the note says so. Fingerprints are
shape based -- numeric literals are masked to ``#`` -- so an equal digest is not
byte equality and a different digest is not a semantic difference. Deep mode
still only reads file bytes, never executes them, and is bounded by
``max_functions`` per side, :data:`DEEP_MAX_INSTRUCTIONS` instructions per
fingerprint, and :data:`MAX_DEEP_FINGERPRINTS` fingerprinted pairs per side;
every bound that cuts work short is reported through ``warnings``. Functions
matched by name after moving, and one-sided functions, are fingerprinted by
neither side of deep mode and keep their structural verdict.

``semantic=True`` adds a *pairing* signal rather than a new structural rule.
After address and name matching, the candidates still unpaired on both sides are
scored with :func:`~codevanta.analysis.function_hash.function_similarity` -- the
multiset overlap of their normalized instruction shapes -- and the
highest-scoring pairs at or above ``threshold`` (default
:data:`DEFAULT_SEMANTIC_THRESHOLD`) are reported as one ``changed`` entry each,
carrying that ``similarity`` (rounded to four decimals). Leftovers that are not
paired keep their structural ``added``/``removed`` verdict, so semantic mode
never hides a one-sided function; it can only turn a remove-plus-add pair into
one change.
Because every score decodes both regions, the pass is bounded twice: at most
:data:`MAX_SEMANTIC_PAIRS` candidate pairs are scored -- the pass is skipped,
with a warning, when the leftover cross product is larger -- and one score
decodes at most :data:`SEMANTIC_MAX_INSTRUCTIONS` instructions per side. A score
is a *shape* overlap, never proof that two functions are the same code.

Matching rules, in order:

1. **By address.** Candidates that share a virtual address are the same
   function; if their metadata (name, size) differs the entry is ``changed``.
   Discovery provenance (``source``/``confidence``) is *not* compared, because
   it describes how a candidate was found, not the binary itself.
2. **By name.** Candidates left over on both sides are matched by name, so a
   function that was relocated is reported as one ``changed`` entry (with the
   old and new address) instead of one removal plus one addition.
3. **By content similarity** (only with ``semantic=True``). The candidates still
   left over on both sides are paired greedily, highest score first, while the
   score is at least ``threshold`` and neither side has been used yet. Each pair
   is reported as one ``changed`` entry carrying ``similarity``.
4. **Everything left over** on the left is ``removed`` and on the right is
   ``added``.

Sections are compared by name, imports by ``(library, name)`` and exports by
name. Consequently a section that changed size/flags at the same name, or an
export that kept its name but moved, is not a delta.

``identical`` therefore means "no structural delta was observed". It does not
imply equal bytes: two different files that expose the same metadata compare as
identical. Sorting and truncation are deterministic (``max_functions``) so the
same inputs always produce the same output.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.analysis.function_hash import (
    DEFAULT_MAX_INSTRUCTIONS,
    function_fingerprint,
    normalized_tokens,
)
from codevanta.core.functions import FunctionCandidate, discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_FUNCTIONS",
    "DEFAULT_SEMANTIC_THRESHOLD",
    "DEEP_MAX_INSTRUCTIONS",
    "MAX_DEEP_FINGERPRINTS",
    "MAX_MAX_FUNCTIONS",
    "MAX_SEMANTIC_PAIRS",
    "MAX_SEMANTIC_THRESHOLD",
    "MIN_MAX_FUNCTIONS",
    "MIN_SEMANTIC_THRESHOLD",
    "SEMANTIC_MAX_INSTRUCTIONS",
    "BinaryDiff",
    "FunctionDelta",
    "diff_binaries",
    "diff_infos",
]

#: Default ceiling on how many function candidates per side are compared.
DEFAULT_MAX_FUNCTIONS = 5_000

#: Smallest accepted ``max_functions``; smaller requests are clamped up.
MIN_MAX_FUNCTIONS = 1

#: Largest accepted ``max_functions``; larger requests are clamped down.
MAX_MAX_FUNCTIONS = 20_000

#: Largest number of address-matched pairs fingerprinted per side in deep mode.
#: Deep mode decodes real instructions, so it needs its own, tighter bound than
#: :data:`DEFAULT_MAX_FUNCTIONS`; pairs above the ceiling keep their structural
#: verdict and are reported through ``warnings``.
MAX_DEEP_FINGERPRINTS = 1_000

#: Instruction ceiling for one deep-mode fingerprint. Equal to
#: :data:`~codevanta.analysis.function_hash.DEFAULT_MAX_INSTRUCTIONS`, so a
#: fingerprint taken during a diff matches one taken on its own.
DEEP_MAX_INSTRUCTIONS = DEFAULT_MAX_INSTRUCTIONS

#: Default minimum shape-similarity score for semantic pairing.
DEFAULT_SEMANTIC_THRESHOLD = 0.9

#: Smallest accepted ``threshold``; anything lower is rejected.
MIN_SEMANTIC_THRESHOLD = 0.0

#: Largest accepted ``threshold``; anything higher is rejected.
MAX_SEMANTIC_THRESHOLD = 1.0

#: Largest number of leftover function pairs scored in semantic mode. Scoring a
#: pair is scored from tokens decoded once per leftover, so the pass needs a bound
#: of its own: when the leftover cross product is larger, semantic pairing is
#: skipped (with a warning)
#: and every leftover keeps its structural ``added``/``removed`` verdict.
MAX_SEMANTIC_PAIRS = 4_096

#: Instruction ceiling per side for one semantic similarity score. Equal to
#: :data:`~codevanta.analysis.function_hash.DEFAULT_MAX_INSTRUCTIONS`, so a score
#: taken during a diff matches one taken on its own.
SEMANTIC_MAX_INSTRUCTIONS = DEFAULT_MAX_INSTRUCTIONS

#: Decimals kept in :attr:`FunctionDelta.similarity`, matching the rounding
#: ``SimilarityResult.to_dict()`` applies, so the field, the evidence note and the
#: JSON report cannot disagree about a score.
_SIMILARITY_DECIMALS = 4

#: ``"added"`` and ``"removed"`` are one-sided; ``"changed"`` covers a metadata
#: edit at the same address, a differing content fingerprint at the same address
#: (deep mode), a relocation matched by name, and a pair matched by shape
#: similarity (semantic mode).
ChangeKind = Literal["added", "removed", "changed"]

_EVIDENCE_SOURCE = "binary_diff.structural"
_EVIDENCE_METHOD = "metadata_compare"
_CAVEAT = (
    "structural metadata only: no instruction bytes were read, compared or executed, "
    "so this is not a semantic equivalence claim"
)
_CONTENT_CAVEAT = (
    "structural metadata plus normalized instruction shapes: numeric literals were masked to "
    "'#', so equal digests are not byte equality and different digests are not a semantic "
    "difference; nothing was executed"
)
_SIMILARITY_CAVEAT = (
    "structural metadata plus normalized instruction-shape similarity: numeric literals were "
    "masked to '#', so a pairing is a shape overlap of decoded instructions and not proof that "
    "two functions are the same code; nothing was executed"
)


@dataclass(frozen=True)
class FunctionDelta:
    """One function-level difference between the two binaries.

    Attributes:
        address: Virtual address the delta is reported at. The right-hand
            address when the candidate exists on the right, otherwise the
            left-hand address.
        name: Best-known name, taken from the right-hand side when it has one.
        change: ``"added"``, ``"removed"`` or ``"changed"``. A function matched
            by name after moving is reported as ``"changed"``.
        left: Metadata snapshot of the left-hand candidate, or ``None`` for an
            ``"added"`` entry.
        right: Metadata snapshot of the right-hand candidate, or ``None`` for a
            ``"removed"`` entry.
        evidence: Why this delta is claimed, including the applicable caveat and
            the specific reason (metadata edit, differing fingerprint, or
            relocation).
        left_digest: Normalized-content fingerprint of the left-hand function,
            set only by deep mode and only when the pair was fingerprinted.
        right_digest: Same for the right-hand function. ``left_digest`` and
            ``right_digest`` are always both set or both ``None``.
        similarity: Shape-similarity score (``0.0 .. 1.0``) of the pair, set only
            by semantic mode and only for a pair that was matched by that score.
            Rounded to four decimals; ``None`` on every structurally matched
            delta, including a name-matched relocation, because those were not
            scored.
    """

    address: int
    name: str | None
    change: ChangeKind
    left: dict[str, Any] | None
    right: dict[str, Any] | None
    evidence: Evidence
    left_digest: str | None = None
    right_digest: str | None = None
    similarity: float | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"address": f"0x{self.address:x}", "change": self.change}
        if self.name:
            data["name"] = self.name
        if self.left is not None:
            data["left"] = dict(self.left)
        if self.right is not None:
            data["right"] = dict(self.right)
        if self.left_digest is not None:
            data["left_digest"] = self.left_digest
        if self.right_digest is not None:
            data["right_digest"] = self.right_digest
        if self.similarity is not None:
            data["similarity"] = self.similarity
        data["evidence"] = self.evidence.to_dict()
        return data


@dataclass(frozen=True)
class BinaryDiff:
    """Structural difference between two binaries.

    Attributes:
        left_path: Path of the left-hand input as loaded.
        right_path: Path of the right-hand input as loaded.
        identical: ``True`` only when no function, section, import or export
            delta was observed. Equal file hashes are neither required nor
            implied.
        functions_added: Candidates present only on the right.
        functions_removed: Candidates present only on the left.
        functions_changed: Candidates matched by address with different metadata
            or -- in deep mode -- a different normalized content fingerprint,
            matched by name after moving, or -- in semantic mode -- paired by
            instruction-shape similarity.
        sections_added: Section names present only on the right.
        sections_removed: Section names present only on the left.
        imports_added: Imports present only on the right, as ``"lib!name"`` when
            a library is known and ``"name"`` otherwise.
        imports_removed: Imports present only on the left, same formatting.
        exports_added: Export names present only on the right.
        exports_removed: Export names present only on the left.
        evidence: Evidence describing the comparison as a whole, with the
            applicable caveat (structural, or structural plus normalized
            content in deep mode, or structural plus shape similarity in semantic
            mode), the effective ``max_functions`` bound, and the deep-mode or
            semantic-mode bounds when that mode ran.
        warnings: Non-fatal problems, including truncation notices.
    """

    left_path: str
    right_path: str
    identical: bool
    functions_added: tuple[FunctionDelta, ...]
    functions_removed: tuple[FunctionDelta, ...]
    functions_changed: tuple[FunctionDelta, ...]
    sections_added: tuple[str, ...]
    sections_removed: tuple[str, ...]
    imports_added: tuple[str, ...]
    imports_removed: tuple[str, ...]
    exports_added: tuple[str, ...]
    exports_removed: tuple[str, ...]
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_path": self.left_path,
            "right_path": self.right_path,
            "identical": self.identical,
            "functions_added": [delta.to_dict() for delta in self.functions_added],
            "functions_removed": [delta.to_dict() for delta in self.functions_removed],
            "functions_changed": [delta.to_dict() for delta in self.functions_changed],
            "sections_added": list(self.sections_added),
            "sections_removed": list(self.sections_removed),
            "imports_added": list(self.imports_added),
            "imports_removed": list(self.imports_removed),
            "exports_added": list(self.exports_added),
            "exports_removed": list(self.exports_removed),
            "evidence": self.evidence.to_dict(),
            "warnings": list(self.warnings),
        }


def _sort_key(candidate: FunctionCandidate) -> tuple[int, str]:
    """Return a stable ordering key for a function candidate."""
    return (candidate.address, candidate.name or "")


def _snapshot(candidate: FunctionCandidate | None) -> dict[str, Any] | None:
    """Return a JSON-safe metadata snapshot of ``candidate``."""
    if candidate is None:
        return None
    data: dict[str, Any] = {
        "address": f"0x{candidate.address:x}",
        "source": candidate.source,
        "confidence": candidate.confidence.value,
    }
    if candidate.name:
        data["name"] = candidate.name
    if candidate.size is not None:
        data["size"] = candidate.size
    return data


def _metadata_differences(left: FunctionCandidate, right: FunctionCandidate) -> tuple[str, ...]:
    """Return the metadata field names that differ between two candidates.

    Only fields describing the function itself are compared. ``source``,
    ``confidence`` and ``evidence`` describe how the candidate was discovered
    and may legitimately differ between two loads of the same file.
    """
    differences: list[str] = []
    if (left.name or None) != (right.name or None):
        differences.append("name")
    if left.size != right.size:
        differences.append("size")
    return tuple(differences)


def _clamp_limit(requested: int, warnings: list[str]) -> int:
    """Clamp ``requested`` into ``[MIN_MAX_FUNCTIONS, MAX_MAX_FUNCTIONS]``.

    Args:
        requested: Caller-supplied ``max_functions`` value.
        warnings: Warning sink; every adjustment is recorded here.

    Returns:
        The effective comparison limit.
    """
    if isinstance(requested, bool) or not isinstance(requested, int):
        warnings.append(
            f"max_functions={requested!r} is not an integer; using {DEFAULT_MAX_FUNCTIONS}"
        )
        return DEFAULT_MAX_FUNCTIONS
    if requested < MIN_MAX_FUNCTIONS:
        warnings.append(
            f"max_functions={requested} is below the supported minimum; "
            f"clamped to {MIN_MAX_FUNCTIONS}"
        )
        return MIN_MAX_FUNCTIONS
    if requested > MAX_MAX_FUNCTIONS:
        warnings.append(
            f"max_functions={requested} exceeds the supported maximum; "
            f"clamped to {MAX_MAX_FUNCTIONS}"
        )
        return MAX_MAX_FUNCTIONS
    return requested


def _validate_threshold(threshold: float) -> float:
    """Return ``threshold`` as a float, rejecting values outside ``0.0 .. 1.0``.

    The threshold is validated in every mode, not only with ``semantic=True``, so
    a caller never gets a silently ignored out-of-range value that would behave
    differently the moment semantic matching is switched on.

    Args:
        threshold: Smallest similarity score that may pair two functions.

    Returns:
        The threshold as a ``float``.

    Raises:
        AnalysisError: When ``threshold`` is not a finite number in
            ``MIN_SEMANTIC_THRESHOLD .. MAX_SEMANTIC_THRESHOLD``.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise AnalysisError(f"threshold must be a number, got {threshold!r}")
    value = float(threshold)
    if not math.isfinite(value) or not (MIN_SEMANTIC_THRESHOLD <= value <= MAX_SEMANTIC_THRESHOLD):
        raise AnalysisError(
            f"threshold must be within {MIN_SEMANTIC_THRESHOLD} .. "
            f"{MAX_SEMANTIC_THRESHOLD}, got {threshold!r}"
        )
    return value


def _bounded(
    functions: Sequence[FunctionCandidate],
    limit: int,
    side: str,
    warnings: list[str],
) -> list[FunctionCandidate]:
    """Return ``functions`` sorted by address, truncated to ``limit`` entries.

    Truncation keeps the lowest addresses so the result stays deterministic and
    records a warning: the added/removed lists may then be incomplete.
    """
    ordered = sorted(functions, key=_sort_key)
    if len(ordered) <= limit:
        return ordered
    warnings.append(
        f"{side} side has {len(ordered)} function candidates, more than "
        f"max_functions={limit}; only the lowest addresses were compared, so "
        "added/removed lists may be incomplete"
    )
    return ordered[:limit]


def _first_by_address(functions: Sequence[FunctionCandidate]) -> dict[int, FunctionCandidate]:
    """Index candidates by address, keeping the first one per address.

    Candidates are expected to be unique per address (as produced by
    :func:`~codevanta.core.functions.discover_functions`); if a duplicate slips
    in, the lowest sorted occurrence wins so the output stays deterministic.
    """
    by_address: dict[int, FunctionCandidate] = {}
    for candidate in sorted(functions, key=_sort_key):
        by_address.setdefault(candidate.address, candidate)
    return by_address


def _group_by_name(candidates: Sequence[FunctionCandidate]) -> dict[str, list[FunctionCandidate]]:
    """Group candidates by name, dropping unnamed ones and preserving order."""
    groups: dict[str, list[FunctionCandidate]] = {}
    for candidate in candidates:
        if not candidate.name:
            continue
        groups.setdefault(candidate.name, []).append(candidate)
    return groups


def _delta(
    change: ChangeKind,
    address: int,
    left: FunctionCandidate | None,
    right: FunctionCandidate | None,
    detail: str,
    *,
    caveat: str = _CAVEAT,
    left_digest: str | None = None,
    right_digest: str | None = None,
    similarity: float | None = None,
) -> FunctionDelta:
    """Assemble one :class:`FunctionDelta` with its caveated evidence record."""
    primary = right if right is not None else left
    return FunctionDelta(
        address=address,
        name=primary.name if primary is not None else None,
        change=change,
        left=_snapshot(left),
        right=_snapshot(right),
        evidence=Evidence(
            source=_EVIDENCE_SOURCE,
            method=_EVIDENCE_METHOD,
            confidence=Confidence.MEDIUM,
            address=address,
            detail=f"{caveat}; {detail}",
        ),
        left_digest=left_digest,
        right_digest=right_digest,
        similarity=similarity,
    )


def _address_digests(
    info: BinaryInfo,
    candidates: Sequence[FunctionCandidate],
    addresses: set[int],
    side: str,
    warnings: list[str],
) -> dict[int, str]:
    """Fingerprint ``candidates`` whose address is in ``addresses``.

    Bounded by construction: ``candidates`` is already truncated to
    ``max_functions`` and ``addresses`` is capped by the caller. Every failure is
    counted rather than raised, so one unreadable function never loses the whole
    comparison; the caller keeps the structural verdict for it.

    Args:
        info: Metadata of the side being fingerprinted.
        candidates: Bounded candidates of that side.
        addresses: Addresses that were matched on both sides.
        side: ``"left"`` or ``"right"``, used in warnings.
        warnings: Warning sink for truncation and failure summaries.

    Returns:
        Mapping of address to normalized-content digest, covering the candidates
        that could be fingerprinted.
    """
    digests: dict[int, str] = {}
    truncated = 0
    first_error: str | None = None
    failed = 0
    for candidate in candidates:
        if candidate.address not in addresses:
            continue
        try:
            fingerprint = function_fingerprint(
                info.path,
                info,
                candidate.address,
                max_instructions=DEEP_MAX_INSTRUCTIONS,
            )
        except (AnalysisError, OSError) as exc:
            failed += 1
            if first_error is None:
                first_error = str(exc)
            continue
        digests[candidate.address] = fingerprint.digest
        if fingerprint.truncated:
            truncated += 1
    if truncated:
        warnings.append(
            f"{side} side: {truncated} fingerprint(s) stopped at "
            f"DEEP_MAX_INSTRUCTIONS={DEEP_MAX_INSTRUCTIONS}; the content comparison covers "
            "only the decoded prefix of those functions"
        )
    if failed:
        warnings.append(
            f"{side} side: {failed} function(s) could not be fingerprinted and were "
            f"compared structurally only (first error: {first_error})"
        )
    return digests


@dataclass(frozen=True)
class _SemanticRequest:
    """Inputs needed to pair leftover functions by shape similarity.

    Attributes:
        left_info: Metadata of the left-hand binary; its ``path`` is read for
            the left-hand scores (read-only, never executed).
        right_info: Metadata of the right-hand binary, same contract.
        threshold: Smallest score that may pair two candidates.
        warnings: Warning sink shared with the enclosing diff, so every bound
            that cuts the pass short reaches the caller.
    """

    left_info: BinaryInfo
    right_info: BinaryInfo
    threshold: float
    warnings: list[str]


def _semantic_pairs(
    left_leftovers: Sequence[FunctionCandidate],
    right_leftovers: Sequence[FunctionCandidate],
    request: _SemanticRequest,
) -> list[tuple[FunctionCandidate, FunctionCandidate, float]]:
    """Pair leftover candidates greedily by normalized instruction similarity.

    Each leftover is decoded once with
    :func:`~codevanta.analysis.function_hash.normalized_tokens` and its token
    multiset is kept, so scoring the cross product costs one multiset overlap per
    pair instead of a fresh decode per pair. Pairs are then considered from the
    highest score down and taken while the score rounds to at least the threshold
    and neither candidate has been paired already. A greedy pass keeps the result
    deterministic and mutually exclusive: one candidate never appears in two
    deltas.

    Work is bounded before it starts: the leftover cross product must fit in
    :data:`MAX_SEMANTIC_PAIRS`, otherwise nothing is scored and a warning says
    so. Each decode is bounded by :data:`SEMANTIC_MAX_INSTRUCTIONS` instructions.
    A leftover that cannot be decoded (unreadable file, address outside an
    executable section, undecodable architecture) is skipped rather than raised,
    so one bad candidate never loses the whole comparison.

    Args:
        left_leftovers: Left-hand candidates no structural rule matched.
        right_leftovers: Right-hand candidates no structural rule matched.
        request: Bounds, metadata and warning sink for the pass.

    Returns:
        ``(left, right, score)`` triples in descending score order, each pair
        reported at the right-hand candidate's address by the caller. ``score`` is
        rounded to ``_SIMILARITY_DECIMALS`` decimals and the threshold is compared
        at the same precision, so a reported score never falls below the
        threshold that authorised it; the ordering uses the unrounded value. A
        pair is never accepted at a rounded score of ``0.0``, so leftovers that
        share no token stay ``added``/``removed`` even with ``threshold=0.0``.
    """
    if not left_leftovers or not right_leftovers:
        return []
    left_sorted = sorted(left_leftovers, key=_sort_key)
    right_sorted = sorted(right_leftovers, key=_sort_key)
    total_pairs = len(left_sorted) * len(right_sorted)
    if total_pairs > MAX_SEMANTIC_PAIRS:
        request.warnings.append(
            f"semantic matching skipped: {len(left_sorted)} left and {len(right_sorted)} "
            f"right leftover function(s) need {total_pairs} pair comparison(s), more than "
            f"MAX_SEMANTIC_PAIRS={MAX_SEMANTIC_PAIRS}; every leftover keeps its "
            "added/removed verdict"
        )
        return []

    left_counts: dict[int, Counter[str]] = {}
    right_counts: dict[int, Counter[str]] = {}
    failed = 0
    first_error: str | None = None
    for candidate in left_sorted:
        try:
            left_counts[candidate.address] = Counter(
                normalized_tokens(
                    request.left_info.path,
                    request.left_info,
                    candidate.address,
                    SEMANTIC_MAX_INSTRUCTIONS,
                )
            )
        except (AnalysisError, OSError) as exc:
            failed += 1
            if first_error is None:
                first_error = str(exc)
    for candidate in right_sorted:
        try:
            right_counts[candidate.address] = Counter(
                normalized_tokens(
                    request.right_info.path,
                    request.right_info,
                    candidate.address,
                    SEMANTIC_MAX_INSTRUCTIONS,
                )
            )
        except (AnalysisError, OSError) as exc:
            failed += 1
            if first_error is None:
                first_error = str(exc)

    if failed:
        request.warnings.append(
            f"semantic matching: {failed} function(s) could not be scored and were left "
            f"unmatched (first error: {first_error})"
        )

    # One decode per leftover: the cross product only overlaps the kept multisets,
    # so the pass is quadratic in comparisons but linear in decoding.
    truncated_sides = sum(
        1
        for counts in (*left_counts.values(), *right_counts.values())
        if sum(counts.values()) >= SEMANTIC_MAX_INSTRUCTIONS
    )
    if truncated_sides:
        request.warnings.append(
            f"semantic matching: {truncated_sides} function(s) were decoded only up to "
            f"SEMANTIC_MAX_INSTRUCTIONS={SEMANTIC_MAX_INSTRUCTIONS} instructions, so their "
            "scores compare prefixes"
        )

    scored: list[tuple[float, FunctionCandidate, FunctionCandidate]] = []
    for left_candidate in left_sorted:
        left_count = left_counts.get(left_candidate.address)
        if left_count is None:
            continue
        for right_candidate in right_sorted:
            right_count = right_counts.get(right_candidate.address)
            if right_count is None:
                continue
            union = sum((left_count | right_count).values())
            if not union:
                # Defensive: a decoded region always carries tokens, but a union of
                # zero would turn every score into 0/0.
                continue
            shared = sum((left_count & right_count).values())
            scored.append((shared / union, left_candidate, right_candidate))

    scored.sort(key=lambda item: (-item[0], item[1].address, item[2].address))
    rounded_threshold = round(request.threshold, _SIMILARITY_DECIMALS)
    used_left: set[int] = set()
    used_right: set[int] = set()
    pairs: list[tuple[FunctionCandidate, FunctionCandidate, float]] = []
    for score, left_candidate, right_candidate in scored:
        rounded_score = round(score, _SIMILARITY_DECIMALS)
        if rounded_score <= 0.0 or rounded_score < rounded_threshold:
            # Scores are sorted descending, so no later pair can qualify either.
            # A rounded zero means the pair shares no token: pairing it would claim
            # a likeness the score denies.
            break
        if left_candidate.address in used_left or right_candidate.address in used_right:
            continue
        used_left.add(left_candidate.address)
        used_right.add(right_candidate.address)
        pairs.append((left_candidate, right_candidate, rounded_score))
    return pairs


def _diff_functions(
    left: Sequence[FunctionCandidate],
    right: Sequence[FunctionCandidate],
    left_digests: Mapping[int, str] | None = None,
    right_digests: Mapping[int, str] | None = None,
    semantic: _SemanticRequest | None = None,
) -> tuple[tuple[FunctionDelta, ...], tuple[FunctionDelta, ...], tuple[FunctionDelta, ...]]:
    """Diff two bounded candidate lists.

    Args:
        left: Bounded, sorted left-hand candidates.
        right: Bounded, sorted right-hand candidates.
        left_digests: Optional address-to-digest map for the left side (deep
            mode). Addresses missing from the map keep their structural verdict.
        right_digests: Same for the right side.
        semantic: Optional request enabling the similarity pass over candidates
            that address and name matching left unpaired. ``None`` keeps the
            structural verdict for those candidates.

    Returns:
        ``(added, removed, changed)`` tuples, each sorted by address.
    """
    left_by_address = _first_by_address(left)
    right_by_address = _first_by_address(right)
    left_digests = left_digests or {}
    right_digests = right_digests or {}

    added: list[FunctionDelta] = []
    removed: list[FunctionDelta] = []
    changed: list[FunctionDelta] = []

    # Pass 1: same address means the same function; compare its metadata and, in
    # deep mode, its normalized content.
    for address in sorted(set(left_by_address) & set(right_by_address)):
        left_candidate = left_by_address[address]
        right_candidate = right_by_address[address]
        differences = _metadata_differences(left_candidate, right_candidate)
        left_digest = left_digests.get(address)
        right_digest = right_digests.get(address)
        if left_digest is not None and right_digest is not None:
            delta_left_digest, delta_right_digest = left_digest, right_digest
        else:
            # Attach a digest pair only when both sides were fingerprinted, so a
            # delta never carries a misleading half pair.
            delta_left_digest, delta_right_digest = None, None
        content_changed = (
            delta_left_digest is not None
            and delta_right_digest is not None
            and delta_left_digest != delta_right_digest
        )
        if not differences and not content_changed:
            continue

        notes: list[str] = []
        if differences:
            notes.append(
                f"metadata changed at the same address 0x{address:x}: {', '.join(differences)}"
            )
        if content_changed:
            notes.append(
                f"content changed at 0x{address:x}: normalized fingerprints differ "
                f"(left {left_digest}, right {right_digest})"
            )
        elif differences and left_digest is not None and right_digest is not None:
            notes.append(
                "normalized fingerprints match, so this is a metadata-only change"
            )
        changed.append(
            _delta(
                "changed",
                address,
                left_candidate,
                right_candidate,
                "; ".join(notes),
                caveat=_CONTENT_CAVEAT if delta_left_digest is not None else _CAVEAT,
                left_digest=delta_left_digest,
                right_digest=delta_right_digest,
            )
        )

    # Pass 2: pair up the leftovers by name so a move is one change, not two.
    left_unmatched = [
        candidate
        for address, candidate in left_by_address.items()
        if address not in right_by_address
    ]
    right_unmatched = [
        candidate
        for address, candidate in right_by_address.items()
        if address not in left_by_address
    ]
    right_by_name = _group_by_name(sorted(right_unmatched, key=_sort_key))

    still_left: list[FunctionCandidate] = []
    matched_right: set[int] = set()
    for candidate in sorted(left_unmatched, key=_sort_key):
        queue = right_by_name.get(candidate.name) if candidate.name else None
        if not queue:
            still_left.append(candidate)
            continue
        partner = queue.pop(0)
        matched_right.add(partner.address)
        changed.append(
            _delta(
                "changed",
                partner.address,
                candidate,
                partner,
                f"matched by name {candidate.name!r} but moved from "
                f"0x{candidate.address:x} to 0x{partner.address:x}",
            )
        )

    # Pass 3 (semantic mode only): pair what is left by shape similarity. Only
    # candidates no structural rule matched are eligible, so the pass can turn a
    # remove-plus-add pair into one change but never overrides an address or name
    # match.
    if semantic is not None:
        right_leftover = [
            candidate
            for candidate in sorted(right_unmatched, key=_sort_key)
            if candidate.address not in matched_right
        ]
        pairs = _semantic_pairs(still_left, right_leftover, semantic)
        if pairs:
            paired_left = {candidate.address for candidate, _partner, _score in pairs}
            matched_right.update(partner.address for _candidate, partner, _score in pairs)
            still_left = [
                candidate for candidate in still_left if candidate.address not in paired_left
            ]
            for left_candidate, right_candidate, score in pairs:
                changed.append(
                    _delta(
                        "changed",
                        right_candidate.address,
                        left_candidate,
                        right_candidate,
                        f"paired by instruction-shape similarity {score:.4f} >= "
                        f"threshold {semantic.threshold:.4f}, moving from "
                        f"0x{left_candidate.address:x} to 0x{right_candidate.address:x}; "
                        "the score compares normalized shapes, it is not proof that the two "
                        "functions are the same code",
                        caveat=_SIMILARITY_CAVEAT,
                        similarity=score,
                    )
                )

    # Pass 4: whatever is left is one-sided.
    for candidate in still_left:
        removed.append(
            _delta(
                "removed",
                candidate.address,
                candidate,
                None,
                f"present only in the left binary at 0x{candidate.address:x}",
            )
        )
    for candidate in sorted(right_unmatched, key=_sort_key):
        if candidate.address in matched_right:
            continue
        added.append(
            _delta(
                "added",
                candidate.address,
                None,
                candidate,
                f"present only in the right binary at 0x{candidate.address:x}",
            )
        )

    changed.sort(key=lambda delta: delta.address)
    removed.sort(key=lambda delta: delta.address)
    added.sort(key=lambda delta: delta.address)
    return tuple(added), tuple(removed), tuple(changed)


def _section_names(info: BinaryInfo) -> set[str]:
    """Return the set of section names exposed by ``info``."""
    return {section.name for section in info.sections}


def _import_keys(info: BinaryInfo) -> set[str]:
    """Return imports as ``"library!name"`` keys, or ``"name"`` without a library.

    The library is part of the key because ``CreateFileA`` from ``kernel32.dll``
    and from another module are different imports.
    """
    keys: set[str] = set()
    for item in info.imports:
        if not item.name:
            continue
        keys.add(f"{item.library}!{item.name}" if item.library else item.name)
    return keys


def _export_names(info: BinaryInfo) -> set[str]:
    """Return the set of export names exposed by ``info``."""
    return {export.name for export in info.exports if export.name}


def diff_infos(
    left_info: BinaryInfo,
    right_info: BinaryInfo,
    left_functions: Sequence[FunctionCandidate],
    right_functions: Sequence[FunctionCandidate],
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    deep: bool = False,
    semantic: bool = False,
    threshold: float = DEFAULT_SEMANTIC_THRESHOLD,
) -> BinaryDiff:
    """Compare two loaded binaries and their function candidates.

    Structural and pure by default: with ``deep=False`` and ``semantic=False``
    nothing is read from disk or executed, and the input sequences are never
    mutated. With ``deep=True`` the function bytes of both sides are read (never
    executed) to fingerprint the address-matched functions; with ``semantic=True``
    they are read to score the functions that address and name matching left
    unpaired. See the module docstring for what each mode adds and what it does
    not.

    Args:
        left_info: Metadata of the left-hand (baseline) binary.
        right_info: Metadata of the right-hand (candidate) binary.
        left_functions: Function candidates discovered in ``left_info``.
        right_functions: Function candidates discovered in ``right_info``.
        max_functions: Per-side ceiling on compared candidates. Values outside
            ``[MIN_MAX_FUNCTIONS, MAX_MAX_FUNCTIONS]`` are clamped and recorded
            in ``warnings``; candidates above the ceiling are dropped (lowest
            addresses are kept) with a truncation warning.
        deep: When true, also fingerprint address-matched functions and report a
            differing normalized fingerprint as ``"changed"`` with both digests
            and a content note.
        semantic: When true, also pair the candidates that address and name
            matching left unpaired when their normalized instruction shapes score
            at least ``threshold``. A pair becomes one ``"changed"`` delta
            carrying ``similarity``; every candidate that is not paired keeps its
            ``"added"``/``"removed"`` verdict.
        threshold: Smallest similarity score that may pair two leftovers, in
            ``[MIN_SEMANTIC_THRESHOLD, MAX_SEMANTIC_THRESHOLD]``. Validated in
            every mode, so an out-of-range value raises even with
            ``semantic=False``.

    Returns:
        A :class:`BinaryDiff` whose ``identical`` flag is ``True`` only when no
        function, section, import or export delta was observed.

    Raises:
        AnalysisError: When ``threshold`` is not a finite number within
            ``0.0 .. 1.0``.
    """
    effective_threshold = _validate_threshold(threshold)
    warnings: list[str] = []
    limit = _clamp_limit(max_functions, warnings)
    left_bounded = _bounded(left_functions, limit, "left", warnings)
    right_bounded = _bounded(right_functions, limit, "right", warnings)

    left_digests: dict[int, str] = {}
    right_digests: dict[int, str] = {}
    if deep:
        matched = {candidate.address for candidate in left_bounded} & {
            candidate.address for candidate in right_bounded
        }
        if len(matched) > MAX_DEEP_FINGERPRINTS:
            warnings.append(
                f"{len(matched)} address-matched function(s) exceed "
                f"MAX_DEEP_FINGERPRINTS={MAX_DEEP_FINGERPRINTS}; only the "
                f"{MAX_DEEP_FINGERPRINTS} lowest addresses were fingerprinted and the rest "
                "were compared structurally"
            )
            matched = set(sorted(matched)[:MAX_DEEP_FINGERPRINTS])
        left_digests = _address_digests(left_info, left_bounded, matched, "left", warnings)
        right_digests = _address_digests(right_info, right_bounded, matched, "right", warnings)

    functions_added, functions_removed, functions_changed = _diff_functions(
        left_bounded,
        right_bounded,
        left_digests,
        right_digests,
        _SemanticRequest(
            left_info=left_info,
            right_info=right_info,
            threshold=effective_threshold,
            warnings=warnings,
        )
        if semantic
        else None,
    )

    left_sections = _section_names(left_info)
    right_sections = _section_names(right_info)
    sections_added = tuple(sorted(right_sections - left_sections))
    sections_removed = tuple(sorted(left_sections - right_sections))

    left_imports = _import_keys(left_info)
    right_imports = _import_keys(right_info)
    imports_added = tuple(sorted(right_imports - left_imports))
    imports_removed = tuple(sorted(left_imports - right_imports))

    left_exports = _export_names(left_info)
    right_exports = _export_names(right_info)
    exports_added = tuple(sorted(right_exports - left_exports))
    exports_removed = tuple(sorted(left_exports - right_exports))

    identical = not any(
        (
            functions_added,
            functions_removed,
            functions_changed,
            sections_added,
            sections_removed,
            imports_added,
            imports_removed,
            exports_added,
            exports_removed,
        )
    )

    extra: dict[str, Any] = {"max_functions": limit}
    caveat = _CAVEAT
    if deep:
        extra["deep"] = True
        extra["deep_instructions"] = DEEP_MAX_INSTRUCTIONS
        extra["max_deep_fingerprints"] = MAX_DEEP_FINGERPRINTS
        caveat = _CONTENT_CAVEAT
    if semantic:
        extra["semantic"] = True
        extra["semantic_threshold"] = effective_threshold
        extra["semantic_instructions"] = SEMANTIC_MAX_INSTRUCTIONS
        extra["max_semantic_pairs"] = MAX_SEMANTIC_PAIRS
        # Both modes read instruction shapes, so the record must keep saying that
        # the content comparison ran instead of dropping its caveat.
        caveat = f"{_CONTENT_CAVEAT}; {_SIMILARITY_CAVEAT}" if deep else _SIMILARITY_CAVEAT
    return BinaryDiff(
        left_path=str(left_info.path),
        right_path=str(right_info.path),
        identical=identical,
        functions_added=functions_added,
        functions_removed=functions_removed,
        functions_changed=functions_changed,
        sections_added=sections_added,
        sections_removed=sections_removed,
        imports_added=imports_added,
        imports_removed=imports_removed,
        exports_added=exports_added,
        exports_removed=exports_removed,
        evidence=Evidence(
            source=_EVIDENCE_SOURCE,
            method=_EVIDENCE_METHOD,
            confidence=Confidence.MEDIUM,
            detail=caveat,
            extra=extra,
        ),
        warnings=tuple(warnings),
    )


def diff_binaries(
    left_path: str | Path,
    right_path: str | Path,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    deep: bool = False,
    semantic: bool = False,
    threshold: float = DEFAULT_SEMANTIC_THRESHOLD,
) -> BinaryDiff:
    """Load two binaries with LIEF and return their structural difference.

    Both files are parsed only; nothing is mapped or executed. Loading errors
    propagate as :class:`~codevanta.core.loader.BinaryLoadError`.

    Args:
        left_path: Path of the left-hand (baseline) binary.
        right_path: Path of the right-hand (candidate) binary.
        max_functions: Per-side ceiling on compared function candidates; see
            :func:`diff_infos`.
        deep: When true, also compare the normalized content of address-matched
            functions (their bytes are read, never executed); see
            :func:`diff_infos`.
        semantic: When true, also pair the functions that address and name
            matching left unpaired when their normalized instruction shapes score
            at least ``threshold``; see :func:`diff_infos`.
        threshold: Smallest similarity score that may pair two leftovers, in
            ``0.0 .. 1.0``; see :func:`diff_infos`.

    Returns:
        The :class:`BinaryDiff` produced by :func:`diff_infos`.

    Raises:
        AnalysisError: When ``threshold`` is not a finite number within
            ``0.0 .. 1.0``.
    """
    # Validate before parsing: a bad threshold must not cost two full loads, and a
    # missing or unreadable file must not mask the threshold error.
    effective_threshold = _validate_threshold(threshold)
    loader = BinaryLoader()
    left_info = loader.load(left_path)
    right_info = loader.load(right_path)
    return diff_infos(
        left_info,
        right_info,
        discover_functions(left_info),
        discover_functions(right_info),
        max_functions=max_functions,
        deep=deep,
        semantic=semantic,
        threshold=effective_threshold,
    )

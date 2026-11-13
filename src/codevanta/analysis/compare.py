"""Typed, offline comparators for two CODEVANTA JSON artifacts.

The differs in :mod:`codevanta.analysis.binary_diff` compare *binaries*: they
load files, decode bytes and fingerprint instructions. This module is their
read-only counterpart for *artifacts*: two ``codevanta analyze`` report payloads
(:file:`samples/report_elf64.json` and friends) or two evidence bundles
(:mod:`codevanta.analysis.evidence_bundle` documents), both already on disk as
JSON. Nothing here reads a target binary, executes anything or touches the
network, so a comparison is reproducible from the two documents alone.

Three comparators, one per question:

* :func:`compare_inventories` -- two function inventories: which functions were
  added, removed, matched by name, and matched by fingerprint (a
  ``function_hash`` digest carried inside the report entries, produced by
  :func:`codevanta.analysis.function_hash.function_fingerprint`).
* :func:`compare_strings` -- new and removed string texts between two reports.
* :func:`compare_bundles` -- two evidence bundles, diffed by record kind (entry
  name) and by digest membership (identical ``sha256`` on both sides means the
  payload bytes are identical, canonical-JSON digests, so equality is exact).

Evidence discipline
-------------------

Every result carries an :class:`~codevanta.evidence.models.Evidence` record
stating how the comparison was made and how far the claim reaches. Name
matching is a *heuristic* (two functions may share a name without sharing code)
and therefore reports ``Confidence.MEDIUM``; fingerprint equality means the two
normalized instruction *shapes* hashed equal -- still not byte equality and not
proof of semantic identity. String-set and bundle-digest comparisons are exact
membership computations over the documents and report ``Confidence.HIGH``.

Bounds
------

Lists are bounded by the ``MAX_*``/``DEFAULT_MAX_*`` constants below, following
the codebase convention: an over-budget input is *truncated* and the result
names the cut in ``warnings`` rather than silently growing. Every result is a
frozen dataclass whose ``to_dict`` is JSON-safe (``allow_nan=False``-clean) and
deterministic: outputs are sorted, no timestamps, no paths beyond what the
caller passed in.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "COMPARE_WHATS",
    "DEFAULT_MAX_FUNCTIONS",
    "DEFAULT_MAX_STRINGS",
    "FINGERPRINT_FIELDS",
    "MAX_COMPARE_ENTRIES",
    "MAX_COMPARE_FUNCTIONS",
    "MAX_COMPARE_STRINGS",
    "BundleCompare",
    "BundleEntryChange",
    "DigestMatch",
    "InventoryCompare",
    "InventoryEntry",
    "NameMatch",
    "StringsCompare",
    "compare_bundles",
    "compare_inventories",
    "compare_strings",
    "is_bundle_document",
    "load_document",
    "load_report_payload",
]

#: Default per-side function-inventory budget for :func:`compare_inventories`.
DEFAULT_MAX_FUNCTIONS = 5_000
#: Hard ceiling for that budget.
MAX_COMPARE_FUNCTIONS = 100_000

#: Default number of string texts kept per delta by :func:`compare_strings`.
DEFAULT_MAX_STRINGS = 2_000
#: Hard ceiling for that budget (mirrors ``core.report.MAX_STRING_LIMIT``).
MAX_COMPARE_STRINGS = 200_000

#: Per-bundle entry cap for :func:`compare_bundles`. A bundle built by
#: :func:`codevanta.analysis.evidence_bundle.build_bundle` holds at most 256
#: entries; this guard exists because the inputs here are arbitrary JSON files.
MAX_COMPARE_ENTRIES = 4_096

#: Report fields compared as ``function_hash`` fingerprints, in lookup order.
FINGERPRINT_FIELDS: tuple[str, ...] = (
    "fingerprint",
    "fingerprint_sha256",
    "function_hash",
)

#: The comparisons the CLI and MCP layers expose.
COMPARE_WHATS: tuple[str, ...] = ("functions", "strings", "bundles")

_EVIDENCE_COMPARE_SOURCE = "compare.json_artifacts"


@dataclass(frozen=True)
class InventoryEntry:
    """One one-sided function from an inventory comparison."""

    name: str | None
    address: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        data: dict[str, Any] = {}
        if self.name is not None:
            data["name"] = self.name
        if self.address is not None:
            data["address"] = self.address
        return data


@dataclass(frozen=True)
class NameMatch:
    """Two functions matched because they share the same non-empty name."""

    name: str
    left_address: str | None
    right_address: str | None
    address_changed: bool

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "name": self.name,
            "left_address": self.left_address,
            "right_address": self.right_address,
            "address_changed": self.address_changed,
        }


@dataclass(frozen=True)
class DigestMatch:
    """Two functions matched because their fingerprint digests are equal."""

    digest: str
    left_name: str | None
    left_address: str | None
    right_name: str | None
    right_address: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "digest": self.digest,
            "left_name": self.left_name,
            "left_address": self.left_address,
            "right_name": self.right_name,
            "right_address": self.right_address,
        }


@dataclass(frozen=True)
class InventoryCompare:
    """Outcome of :func:`compare_inventories`; frozen and JSON-safe."""

    left_functions: int
    right_functions: int
    added: tuple[InventoryEntry, ...] = ()
    removed: tuple[InventoryEntry, ...] = ()
    matched_by_name: tuple[NameMatch, ...] = ()
    matched_by_fingerprint: tuple[DigestMatch, ...] = ()
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "functions",
            "left_functions": self.left_functions,
            "right_functions": self.right_functions,
            "added": [entry.to_dict() for entry in self.added],
            "added_count": len(self.added),
            "removed": [entry.to_dict() for entry in self.removed],
            "removed_count": len(self.removed),
            "matched_by_name": [match.to_dict() for match in self.matched_by_name],
            "matched_by_name_count": len(self.matched_by_name),
            "matched_by_fingerprint": [
                match.to_dict() for match in self.matched_by_fingerprint
            ],
            "matched_by_fingerprint_count": len(self.matched_by_fingerprint),
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class StringsCompare:
    """Outcome of :func:`compare_strings`; frozen and JSON-safe."""

    left_strings: int
    right_strings: int
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    shared_count: int = 0
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "strings",
            "left_strings": self.left_strings,
            "right_strings": self.right_strings,
            "added": list(self.added),
            "added_count": len(self.added),
            "removed": list(self.removed),
            "removed_count": len(self.removed),
            "shared_count": self.shared_count,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class BundleEntryChange:
    """One entry present under the same name with different payload digests."""

    name: str
    left_sha256: str | None
    right_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "name": self.name,
            "left_sha256": self.left_sha256,
            "right_sha256": self.right_sha256,
        }


@dataclass(frozen=True)
class BundleCompare:
    """Outcome of :func:`compare_bundles`; frozen and JSON-safe."""

    left_entries: int
    right_entries: int
    added_names: tuple[str, ...] = ()
    removed_names: tuple[str, ...] = ()
    changed: tuple[BundleEntryChange, ...] = ()
    unchanged_names: tuple[str, ...] = ()
    shared_digest_count: int = 0
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "bundles",
            "left_entries": self.left_entries,
            "right_entries": self.right_entries,
            "added_names": list(self.added_names),
            "added_count": len(self.added_names),
            "removed_names": list(self.removed_names),
            "removed_count": len(self.removed_names),
            "changed": [change.to_dict() for change in self.changed],
            "changed_count": len(self.changed),
            "unchanged_names": list(self.unchanged_names),
            "unchanged_count": len(self.unchanged_names),
            "shared_digest_count": self.shared_digest_count,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _address_text(entry: Mapping[str, Any]) -> str | None:
    """Return the address of a report entry as display text, or ``None``."""
    address = entry.get("address")
    if isinstance(address, int) and not isinstance(address, bool):
        return f"0x{address:x}"
    if isinstance(address, str) and address.strip():
        return address
    return None


def _entry_name(entry: Mapping[str, Any]) -> str | None:
    """Return the name of a report entry, or ``None`` when absent or blank."""
    name = entry.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return None


def _is_sha256(value: str) -> bool:
    """``True`` when ``value`` looks like a lowercase 64-hex digest."""
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _entry_digest(entry: Mapping[str, Any], warnings: list[str], side: str) -> str | None:
    """Return the first well-formed fingerprint digest of a report entry."""
    for field_name in FINGERPRINT_FIELDS:
        value = entry.get(field_name)
        if isinstance(value, str) and value.strip():
            text = value.strip().lower()
            if _is_sha256(text):
                return text
            warnings.append(
                f"{side}: function field {field_name!r} is not a sha256 hex digest; ignored"
            )
    return None


def _function_inventory(
    payload: Mapping[str, Any],
    budget: int,
    side: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    """Extract and bound the function list of an analyze report payload."""
    functions = payload.get("functions")
    if not isinstance(functions, list):
        raise AnalysisError(f"{side}: payload has no 'functions' list")
    if len(functions) > budget:
        warnings.append(
            f"{side}: function inventory truncated, keeping the first {budget} "
            f"of {len(functions)} entries"
        )
    kept = []
    for entry in functions[:budget]:
        if isinstance(entry, Mapping):
            kept.append(dict(entry))
        else:
            warnings.append(f"{side}: non-object function entry ignored")
    return kept


def _dedupe_warnings(warnings: list[str]) -> tuple[str, ...]:
    """Return warnings in first-seen order without duplicates."""
    seen: set[str] = set()
    ordered: list[str] = []
    for warning in warnings:
        if warning not in seen:
            seen.add(warning)
            ordered.append(warning)
    return tuple(ordered)


def compare_inventories(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
) -> InventoryCompare:
    """Compare two function inventories from analyze report payloads.

    Matching passes, in order:

    1. **By name.** Entries that share a non-empty ``name`` are the same
       function (``matched_by_name``). A name that occurs more than once on
       either side is ambiguous and is skipped, with a warning, rather than
       paired arbitrarily.
    2. **By fingerprint.** Unmatched entries carrying a ``function_hash``
       digest (:data:`FINGERPRINT_FIELDS`) are paired when the digest occurs
       exactly once on each side (``matched_by_fingerprint``). A digest is a
       normalized instruction-*shape* hash, so equality is not byte equality.
    3. **One-sided leftovers.** Still-unmatched entries become ``removed``
       (left only) or ``added`` (right only). Neither side of a pair is hidden
       by a heuristic match.

    Args:
        left: The left (baseline) analyze report payload.
        right: The right (comparison) analyze report payload.
        max_functions: Per-side inventory budget
            (``1`` .. :data:`MAX_COMPARE_FUNCTIONS`); larger inventories are
            truncated with a warning.

    Returns:
        A frozen :class:`InventoryCompare`.

    Raises:
        AnalysisError: When a payload has no ``functions`` list or the budget
            is out of range.
    """
    if max_functions < 1 or max_functions > MAX_COMPARE_FUNCTIONS:
        raise AnalysisError(f"max_functions must be between 1 and {MAX_COMPARE_FUNCTIONS}")
    warnings: list[str] = []
    left_entries = _function_inventory(left, max_functions, "left", warnings)
    right_entries = _function_inventory(right, max_functions, "right", warnings)

    # Pass 1: match by non-empty name; ambiguous (duplicated) names are skipped.
    left_by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in left_entries:
        name = _entry_name(entry)
        if name is not None:
            left_by_name.setdefault(name, []).append(entry)
    right_by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in right_entries:
        name = _entry_name(entry)
        if name is not None:
            right_by_name.setdefault(name, []).append(entry)

    matched_left: set[int] = set()
    matched_right: set[int] = set()
    name_matches: list[NameMatch] = []
    ambiguous: set[str] = set()
    for name in sorted(set(left_by_name) & set(right_by_name)):
        if len(left_by_name[name]) > 1 or len(right_by_name[name]) > 1:
            ambiguous.add(name)
            continue
        left_entry = left_by_name[name][0]
        right_entry = right_by_name[name][0]
        left_address = _address_text(left_entry)
        right_address = _address_text(right_entry)
        name_matches.append(
            NameMatch(
                name=name,
                left_address=left_address,
                right_address=right_address,
                address_changed=left_address != right_address,
            )
        )
        matched_left.add(id(left_entry))
        matched_right.add(id(right_entry))
    if ambiguous:
        names = ", ".join(sorted(ambiguous))
        warnings.append(f"ambiguous duplicated names skipped for name matching: {names}")

    # Pass 2: match leftovers by fingerprint digest, unique on both sides.
    left_digests: dict[str, list[dict[str, Any]]] = {}
    right_digests: dict[str, list[dict[str, Any]]] = {}
    for entry in left_entries:
        if id(entry) in matched_left:
            continue
        digest = _entry_digest(entry, warnings, "left")
        if digest is not None:
            left_digests.setdefault(digest, []).append(entry)
    for entry in right_entries:
        if id(entry) in matched_right:
            continue
        digest = _entry_digest(entry, warnings, "right")
        if digest is not None:
            right_digests.setdefault(digest, []).append(entry)

    fingerprint_matches: list[DigestMatch] = []
    for digest in sorted(set(left_digests) & set(right_digests)):
        if len(left_digests[digest]) > 1 or len(right_digests[digest]) > 1:
            warnings.append(f"fingerprint {digest[:12]}.. is duplicated on a side; skipped")
            continue
        left_entry = left_digests[digest][0]
        right_entry = right_digests[digest][0]
        fingerprint_matches.append(
            DigestMatch(
                digest=digest,
                left_name=_entry_name(left_entry),
                left_address=_address_text(left_entry),
                right_name=_entry_name(right_entry),
                right_address=_address_text(right_entry),
            )
        )
        matched_left.add(id(left_entry))
        matched_right.add(id(right_entry))

    # Pass 3: whatever is left is one-sided.
    added = [
        InventoryEntry(name=_entry_name(entry), address=_address_text(entry))
        for entry in right_entries
        if id(entry) not in matched_right
    ]
    removed = [
        InventoryEntry(name=_entry_name(entry), address=_address_text(entry))
        for entry in left_entries
        if id(entry) not in matched_left
    ]
    added.sort(key=lambda entry: (entry.name or "", entry.address or ""))
    removed.sort(key=lambda entry: (entry.name or "", entry.address or ""))

    evidence = Evidence(
        source=_EVIDENCE_COMPARE_SOURCE,
        method="name_and_fingerprint_matching",
        confidence=Confidence.MEDIUM,
        detail=(
            "functions matched by shared non-empty name (a heuristic) and then by "
            "function_hash fingerprint (equal normalized instruction shapes, not "
            "byte equality); one-sided entries are reported unfiltered"
        ),
    )
    return InventoryCompare(
        left_functions=len(left_entries),
        right_functions=len(right_entries),
        added=tuple(added),
        removed=tuple(removed),
        matched_by_name=tuple(sorted(name_matches, key=lambda match: match.name)),
        matched_by_fingerprint=tuple(
            sorted(fingerprint_matches, key=lambda match: match.digest)
        ),
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


def _string_texts(
    payload: Mapping[str, Any],
    budget: int,
    side: str,
    warnings: list[str],
) -> tuple[list[str], int]:
    """Extract the unique string texts of a report, bounded by ``budget``."""
    strings = payload.get("strings")
    if not isinstance(strings, Mapping):
        raise AnalysisError(f"{side}: payload has no 'strings' section")
    items = strings.get("items")
    if not isinstance(items, list):
        raise AnalysisError(f"{side}: payload strings section has no 'items' list")
    texts: set[str] = set()
    for item in items:
        if isinstance(item, Mapping):
            text = item.get("text")
            if isinstance(text, str) and text:
                texts.add(text)
        else:
            warnings.append(f"{side}: non-object string item ignored")
    ordered = sorted(texts)
    if len(ordered) > budget:
        warnings.append(
            f"{side}: string texts truncated, keeping the first {budget} "
            f"of {len(ordered)} unique texts"
        )
        ordered = ordered[:budget]
    return ordered, len(items)


def compare_strings(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> StringsCompare:
    """Compare the extracted string texts of two analyze report payloads.

    The comparison is exact set membership over the unique ``text`` values of
    each report's ``strings.items``: an entry is *added* when its text appears
    only on the right, *removed* when it appears only on the left. Identical
    text at different offsets, or in different encodings, is one entry -- the
    evidence record says so. Outputs are sorted and bounded by ``max_strings``
    (``1`` .. :data:`MAX_COMPARE_STRINGS`), with the cut reported in
    ``warnings``.

    Raises:
        AnalysisError: When a payload has no ``strings`` section/items or the
            budget is out of range.
    """
    if max_strings < 1 or max_strings > MAX_COMPARE_STRINGS:
        raise AnalysisError(f"max_strings must be between 1 and {MAX_COMPARE_STRINGS}")
    warnings: list[str] = []
    left_texts, left_items = _string_texts(left, max_strings, "left", warnings)
    right_texts, right_items = _string_texts(right, max_strings, "right", warnings)
    left_set = set(left_texts)
    right_set = set(right_texts)
    evidence = Evidence(
        source=_EVIDENCE_COMPARE_SOURCE,
        method="string_set_diff",
        confidence=Confidence.HIGH,
        detail=(
            "exact set membership over the unique strings.items text values; "
            "identical text at different offsets or encodings counts once, and "
            "offset/encoding changes are not reported"
        ),
    )
    return StringsCompare(
        left_strings=left_items,
        right_strings=right_items,
        added=tuple(sorted(right_set - left_set)),
        removed=tuple(sorted(left_set - right_set)),
        shared_count=len(left_set & right_set),
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


def _bundle_entries(
    document: Mapping[str, Any],
    side: str,
    warnings: list[str],
) -> dict[str, str | None]:
    """Extract ``{entry name: payload sha256}`` from an evidence bundle doc."""
    entries = document.get("entries")
    if not isinstance(entries, Mapping):
        raise AnalysisError(f"{side}: document has no 'entries' object")
    names = sorted(str(name) for name in entries)
    if len(names) > MAX_COMPARE_ENTRIES:
        warnings.append(
            f"{side}: entries truncated, keeping the first {MAX_COMPARE_ENTRIES} "
            f"of {len(names)}"
        )
        names = names[:MAX_COMPARE_ENTRIES]
    digests: dict[str, str | None] = {}
    for name in names:
        record = entries.get(name)
        if not isinstance(record, Mapping):
            warnings.append(f"{side}: entry {name!r} is not an object")
            digests[name] = None
            continue
        digest = record.get("sha256")
        if isinstance(digest, str) and _is_sha256(digest.strip().lower()):
            digests[name] = digest.strip().lower()
        else:
            warnings.append(f"{side}: entry {name!r} has no usable sha256 digest")
            digests[name] = None
    return digests


def compare_bundles(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> BundleCompare:
    """Diff two evidence-bundle documents by record kind and digest membership.

    *Record kind* is the entry name: names present on only one side are added
    or removed. For names present on both sides, the recorded payload digests
    decide: equal non-``None`` digests mean the canonical JSON payload bytes
    are *identical* (``unchanged_names``), different digests mean the entry's
    content changed (``changed``). ``shared_digest_count`` counts the digests
    that appear anywhere in both bundles, so an entry renamed between builds
    still shows up as shared content. Bundle manifests (timestamps, subject)
    are deliberately ignored: this compares recorded evidence, not metadata.

    This function does *not* re-verify digests -- a tampered bundle compares
    by what it claims. Verify first with
    :func:`codevanta.analysis.evidence_bundle.verify_bundle` when integrity
    matters.

    Raises:
        AnalysisError: When a document has no ``entries`` object.
    """
    warnings: list[str] = []
    left_digests = _bundle_entries(left, "left", warnings)
    right_digests = _bundle_entries(right, "right", warnings)

    added_names = sorted(set(right_digests) - set(left_digests))
    removed_names = sorted(set(left_digests) - set(right_digests))
    changed: list[BundleEntryChange] = []
    unchanged: list[str] = []
    for name in sorted(set(left_digests) & set(right_digests)):
        left_digest = left_digests[name]
        right_digest = right_digests[name]
        if left_digest is not None and left_digest == right_digest:
            unchanged.append(name)
        else:
            changed.append(
                BundleEntryChange(
                    name=name,
                    left_sha256=left_digest,
                    right_sha256=right_digest,
                )
            )
    left_digest_values = {digest for digest in left_digests.values() if digest is not None}
    right_digest_values = {digest for digest in right_digests.values() if digest is not None}

    evidence = Evidence(
        source=_EVIDENCE_COMPARE_SOURCE,
        method="digest_membership",
        confidence=Confidence.HIGH,
        detail=(
            "record kinds are entry names; equal canonical-JSON sha256 digests "
            "mean identical payload bytes; manifests (created_at, subject) are "
            "ignored and digests are taken as recorded, not re-verified"
        ),
    )
    return BundleCompare(
        left_entries=len(left_digests),
        right_entries=len(right_digests),
        added_names=tuple(added_names),
        removed_names=tuple(removed_names),
        changed=tuple(changed),
        unchanged_names=tuple(unchanged),
        shared_digest_count=len(left_digest_values & right_digest_values),
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


def is_bundle_document(document: Mapping[str, Any]) -> bool:
    """``True`` when ``document`` looks like an evidence-bundle document.

    A bundle has a ``manifest`` and an ``entries`` object; an analyze report
    payload has neither.
    """
    return isinstance(document.get("manifest"), Mapping) and isinstance(
        document.get("entries"), Mapping
    )


def load_document(path: str | Path) -> dict[str, Any]:
    """Read a JSON file and return it as a mapping (no unwrapping).

    Raises:
        AnalysisError: When the file cannot be read, is not valid JSON or is
            not a JSON object.
    """
    target = Path(path)
    try:
        with target.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"{target} is not UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise AnalysisError(f"cannot read {target}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"{target} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AnalysisError(f"{target} is not a JSON object")
    return document


def load_report_payload(path: str | Path) -> dict[str, Any]:
    """Read a JSON artifact and return the analyze report payload to compare.

    A plain analyze report is returned as-is; an evidence-bundle document is
    unwrapped to its ``report`` entry payload, so
    ``samples/report_elf64.json`` and ``samples/report_bundle.json`` can be
    compared without any preprocessing.

    Raises:
        AnalysisError: When the file is unreadable/not JSON, or when it is a
            bundle without a ``report`` entry.
    """
    document = load_document(path)
    if not is_bundle_document(document):
        return document
    entries = document["entries"]
    report = entries.get("report")
    if not isinstance(report, Mapping) or not isinstance(report.get("payload"), Mapping):
        raise AnalysisError(
            f"{path} is an evidence bundle without a 'report' entry; "
            "function/string comparisons need analyze report payloads"
        )
    return dict(report["payload"])

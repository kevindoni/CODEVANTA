"""Typed, offline comparators for two CODEVANTA JSON artifacts.

The differs in :mod:`codevanta.analysis.binary_diff` compare *binaries*: they
load files, decode bytes and fingerprint instructions. This module is their
read-only counterpart for *artifacts*: two ``codevanta analyze`` report payloads
(:file:`samples/report_elf64.json` and friends) or two evidence bundles
(:mod:`codevanta.analysis.evidence_bundle` documents), both already on disk as
JSON. Nothing here reads a target binary, executes anything or touches the
network, so a comparison is reproducible from the two documents alone.

Twelve comparators, one per question:

* :func:`compare_inventories` -- two function inventories: which functions were
  added, removed, matched by name, and matched by fingerprint (a
  ``function_hash`` digest carried inside the report entries, produced by
  :func:`codevanta.analysis.function_hash.function_fingerprint`).
* :func:`compare_strings` -- new and removed string texts between two reports.
* :func:`compare_bundles` -- two evidence bundles, diffed by record kind (entry
  name) and by digest membership (identical ``sha256`` on both sides means the
  payload bytes are identical, canonical-JSON digests, so equality is exact).
* :func:`compare_reports` -- two analyze report payloads diffed structurally:
  which top-level sections (``functions``, ``strings``, ``binary``, ...) are
  present, added, removed or changed, keyed by the sha256 of each section's
  canonical JSON, plus per-path element counts.
* :func:`compare_wasm` -- two WASM modules through
  :func:`codevanta.analysis.containers.inspect_wasm`: section sets, bounded
  import/export name diffs and byte-size deltas.
* :func:`compare_metadata` -- two ``binmeta`` ``MetadataReport`` documents:
  format-kind changes and a key-level diff of the ``details`` dicts.
* :func:`compare_crash` -- two ELF core dumps through
  :func:`codevanta.analysis.crash_core.parse_core_dump`: same signal, same
  faulting module, a bounded register-delta table and a ``same_crash_site``
  verdict with confidence.
* :func:`compare_sessions` -- two CODEVANTA session databases (via
  :mod:`codevanta.analysis.sqlite_view`): annotation count deltas and the
  annotated addresses found on only one side.
* :func:`compare_nav` -- two session databases read through
  :class:`codevanta.analysis.nav.NavStore`: bookmark/comment/cursor diffs.
* :func:`compare_firmware` -- two firmware images through
  :func:`codevanta.analysis.containers.scan_magics`: signature hits that
  appeared or disappeared, keyed by offset and container kind.
* :func:`compare_screenshots` -- two captured PNG screenshots through
  :func:`codevanta.analysis.png_diff.pixel_diff`: exact local pixel
  metrics (changed-pixel ratio, per-channel mean deltas) with an
  ``identical``/``minor``/``major`` verdict, no OCR involved.
* :func:`compare_har` -- two HAR capture files through
  :mod:`codevanta.analysis.har_capture`: entry-count delta, new/removed
  URL paths, status-code changes and method histogram deltas.

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

import hashlib
import json
import sqlite3
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis.containers import (
    WasmSummary,
    inspect_wasm,
    load_container_bytes,
    scan_magics,
)
from codevanta.analysis.crash_core import CoreDumpSummary, parse_core_dump
from codevanta.analysis.nav import NavStore
from codevanta.analysis.png_diff import ScreenshotDiff, pixel_diff
from codevanta.analysis.sqlite_view import inspect_sqlite
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "COMPARE_WHATS",
    "DEFAULT_MAX_FUNCTIONS",
    "DEFAULT_MAX_STRINGS",
    "DEFAULT_MAX_CHANGED_SECTIONS",
    "DEFAULT_MAX_DETAIL_KEYS",
    "DEFAULT_MAX_ROWS",
    "FINGERPRINT_FIELDS",
    "JSON_COMPARE_WHATS",
    "MAX_COMPARE_ENTRIES",
    "MAX_COMPARE_FUNCTIONS",
    "MAX_COMPARE_REGISTERS",
    "MAX_COMPARE_STRINGS",
    "MAX_COMPARE_CHANGED_SECTIONS",
    "MAX_COMPARE_DETAIL_KEYS",
    "MAX_COMPARE_ROWS",
    "PATH_COMPARE_WHATS",
    "REPORT_COUNT_PATHS",
    "BundleCompare",
    "BundleEntryChange",
    "CrashCompare",
    "DigestMatch",
    "FirmwareCompare",
    "HarCompare",
    "HarMethodDelta",
    "HarStatusChange",
    "InventoryCompare",
    "InventoryEntry",
    "MetadataCompare",
    "MetadataDetailChange",
    "NameMatch",
    "NavCompare",
    "RegisterDelta",
    "ReportsCompare",
    "ReportsSectionChange",
    "ScreenshotCompare",
    "SectionCount",
    "SessionsCompare",
    "StringsCompare",
    "WasmCompare",
    "WasmSectionDelta",
    "compare_artifacts",
    "compare_bundles",
    "compare_crash",
    "compare_firmware",
    "compare_har",
    "compare_inventories",
    "compare_metadata",
    "compare_nav",
    "compare_reports",
    "compare_screenshots",
    "compare_sessions",
    "compare_strings",
    "compare_wasm",
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

#: The comparisons the CLI and MCP layers expose, in dispatch order: the
#: first five take JSON documents, the rest take file paths.
COMPARE_WHATS: tuple[str, ...] = (
    "functions",
    "strings",
    "bundles",
    "reports",
    "metadata",
    "wasm",
    "crash",
    "sessions",
    "nav",
    "firmware",
    "screenshots",
    "har",
)

#: The members of :data:`COMPARE_WHATS` whose inputs are JSON documents.
JSON_COMPARE_WHATS: tuple[str, ...] = (
    "functions",
    "strings",
    "bundles",
    "reports",
    "metadata",
)

#: The members of :data:`COMPARE_WHATS` whose inputs are file paths
#: (WASM modules, core dumps, session databases, firmware images,
#: screenshots, HAR captures).
PATH_COMPARE_WHATS: tuple[str, ...] = (
    "wasm",
    "crash",
    "sessions",
    "nav",
    "firmware",
    "screenshots",
    "har",
)

#: Default number of changed report sections kept as detail rows by
#: :func:`compare_reports`.
DEFAULT_MAX_CHANGED_SECTIONS = 16
#: Hard ceiling for that budget.
MAX_COMPARE_CHANGED_SECTIONS = 160

#: Default number of changed metadata detail keys kept by
#: :func:`compare_metadata`.
DEFAULT_MAX_DETAIL_KEYS = 32
#: Hard ceiling for that budget.
MAX_COMPARE_DETAIL_KEYS = 320

#: Default per-delta row budget shared by :func:`compare_sessions`,
#: :func:`compare_nav` and the common-section table of :func:`compare_wasm`.
DEFAULT_MAX_ROWS = 64
#: Hard ceiling for that budget.
MAX_COMPARE_ROWS = 640

#: Default number of URL paths kept per delta by :func:`compare_har`.
DEFAULT_MAX_HAR_PATHS = 64
#: Hard ceiling for that budget.
MAX_COMPARE_HAR_PATHS = 640

#: Fixed width of the register-delta table in :func:`compare_crash` (the
#: x86_64 general-purpose register file); excess registers are summarised
#: in ``warnings``.
MAX_COMPARE_REGISTERS = 16

#: Report payload paths compared as element counts by
#: :func:`compare_reports`, in output order.
REPORT_COUNT_PATHS: tuple[str, ...] = (
    "functions",
    "strings",
    "binary.sections",
    "binary.imports",
    "binary.exports",
    "binary.symbols",
    "disassembly.instruction_count",
)

_EVIDENCE_COMPARE_SOURCE = "compare.json_artifacts"
_EVIDENCE_REPORT_SOURCE = "compare.reports"
_EVIDENCE_METADATA_SOURCE = "compare.metadata"
_EVIDENCE_WASM_SOURCE = "compare.wasm"
_EVIDENCE_CRASH_SOURCE = "compare.crash"
_EVIDENCE_SESSIONS_SOURCE = "compare.sessions"
_EVIDENCE_NAV_SOURCE = "compare.nav"
_EVIDENCE_FIRMWARE_SOURCE = "compare.firmware"
_EVIDENCE_SCREENSHOT_SOURCE = "compare.screenshots"
_EVIDENCE_HAR_SOURCE = "compare.har"


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


# ---------------------------------------------------------------------------
# shared helpers for the comparators below
# ---------------------------------------------------------------------------


def _canonical_sha256(value: Any) -> str:
    """sha256 of a value's canonical JSON encoding (sorted keys, compact)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mapping_side(value: Any, side: str) -> Mapping[str, Any]:
    """Return ``value`` as a mapping or raise a side-labelled typed error."""
    if not isinstance(value, Mapping):
        raise AnalysisError(f"{side}: payload is not a JSON object")
    return value


def _string_keys(document: Mapping[str, Any], side: str, warnings: list[str]) -> list[str]:
    """Sorted string keys of ``document``; non-string keys warn and drop."""
    keys = []
    for key in document:
        if isinstance(key, str):
            keys.append(key)
        else:
            warnings.append(f"{side}: non-string section name {key!r} ignored")
    return sorted(keys)


def _bounded(
    label: str, items: list[Any], budget: int, warnings: list[str]
) -> list[Any]:
    """Keep at most ``budget`` items, appending a truncation warning when cut."""
    if len(items) > budget:
        warnings.append(f"{label}: kept {budget} of {len(items)}")
        return items[:budget]
    return items


# ---------------------------------------------------------------------------
# compare_reports -- structural diff of two analyze report payloads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SectionCount:
    """One element count from :data:`REPORT_COUNT_PATHS`, per side."""

    path: str
    left: int | None
    right: int | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection; ``delta`` only when both sides counted."""
        data: dict[str, Any] = {"path": self.path, "left": self.left, "right": self.right}
        if self.left is not None and self.right is not None:
            data["delta"] = self.right - self.left
        return data


@dataclass(frozen=True)
class ReportsSectionChange:
    """One report section whose canonical-JSON digest changed."""

    name: str
    left_sha256: str
    right_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "name": self.name,
            "left_sha256": self.left_sha256,
            "right_sha256": self.right_sha256,
        }


@dataclass(frozen=True)
class ReportsCompare:
    """Outcome of :func:`compare_reports`; frozen and JSON-safe."""

    left_sections: int
    right_sections: int
    added_sections: tuple[str, ...] = ()
    removed_sections: tuple[str, ...] = ()
    changed: tuple[ReportsSectionChange, ...] = ()
    unchanged_sections: tuple[str, ...] = ()
    section_counts: tuple[SectionCount, ...] = ()
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "reports",
            "left_sections": self.left_sections,
            "right_sections": self.right_sections,
            "added_sections": list(self.added_sections),
            "added_count": len(self.added_sections),
            "removed_sections": list(self.removed_sections),
            "removed_count": len(self.removed_sections),
            "changed": [change.to_dict() for change in self.changed],
            "changed_count": len(self.changed),
            "unchanged_sections": list(self.unchanged_sections),
            "unchanged_count": len(self.unchanged_sections),
            "section_counts": [count.to_dict() for count in self.section_counts],
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _count_at_path(payload: Mapping[str, Any], dotted: str) -> int | None:
    """Resolve a dotted path to an element count, or ``None`` when absent.

    Lists count their elements; mappings prefer an integer ``count`` field
    then the length of an ``items`` list; plain integers are taken as-is.
    """
    node: Any = payload
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    if isinstance(node, list):
        return len(node)
    if isinstance(node, bool):
        return None
    if isinstance(node, int):
        return node
    if isinstance(node, Mapping):
        count = node.get("count")
        if isinstance(count, int) and not isinstance(count, bool):
            return count
        items = node.get("items")
        if isinstance(items, list):
            return len(items)
    return None


def compare_reports(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    max_changed_sections: int = DEFAULT_MAX_CHANGED_SECTIONS,
) -> ReportsCompare:
    """Structurally diff two analyze report payloads.

    Every top-level section is fingerprinted by the sha256 of its canonical
    JSON (sorted keys, compact separators), so a section counts as changed
    only when its serialized content differs after normalization. Sections
    present on one side only are ``added_sections`` (right) or
    ``removed_sections`` (left); per-path element counts from
    :data:`REPORT_COUNT_PATHS` are reported per side with a delta. The
    changed-section detail list is bounded at ``max_changed_sections`` with
    a truncation warning.

    Args:
        left: The left (baseline) report payload.
        right: The right (comparison) report payload.
        max_changed_sections: Detail-row budget (``1`` ..
            :data:`MAX_COMPARE_CHANGED_SECTIONS`).

    Returns:
        A frozen :class:`ReportsCompare`; ``identical`` is ``True`` when no
        section was added, removed or changed.

    Raises:
        AnalysisError: When a payload is not a JSON object or the budget is
            out of range.
    """
    if max_changed_sections < 1 or max_changed_sections > MAX_COMPARE_CHANGED_SECTIONS:
        raise AnalysisError(
            f"max_changed_sections must be between 1 and {MAX_COMPARE_CHANGED_SECTIONS}"
        )
    warnings: list[str] = []
    left_map = _mapping_side(left, "left")
    right_map = _mapping_side(right, "right")
    left_keys = _string_keys(left_map, "left", warnings)
    right_keys = _string_keys(right_map, "right", warnings)
    left_digests = {key: _canonical_sha256(left_map[key]) for key in left_keys}
    right_digests = {key: _canonical_sha256(right_map[key]) for key in right_keys}

    added = sorted(set(right_keys) - set(left_keys))
    removed = sorted(set(left_keys) - set(right_keys))
    common = sorted(set(left_keys) & set(right_keys))
    changed_rows = [
        ReportsSectionChange(
            name=key, left_sha256=left_digests[key], right_sha256=right_digests[key]
        )
        for key in common
        if left_digests[key] != right_digests[key]
    ]
    unchanged = [key for key in common if left_digests[key] == right_digests[key]]
    changed_kept = _bounded(
        "changed sections", changed_rows, max_changed_sections, warnings
    )
    counts = tuple(
        SectionCount(
            path=path,
            left=_count_at_path(left_map, path),
            right=_count_at_path(right_map, path),
        )
        for path in REPORT_COUNT_PATHS
        if _count_at_path(left_map, path) is not None
        or _count_at_path(right_map, path) is not None
    )
    identical = not added and not removed and not changed_rows
    evidence = Evidence(
        source=_EVIDENCE_REPORT_SOURCE,
        method="report_section_sha_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(changed_rows)} of {len(common)} shared sections changed; "
            "digests are canonical-JSON sha256"
        ),
    )
    return ReportsCompare(
        left_sections=len(left_keys),
        right_sections=len(right_keys),
        added_sections=tuple(added),
        removed_sections=tuple(removed),
        changed=tuple(changed_kept),
        unchanged_sections=tuple(unchanged),
        section_counts=counts,
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_metadata -- two binmeta MetadataReport documents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetadataDetailChange:
    """One ``details`` key whose canonical-JSON value changed."""

    key: str
    left: Any
    right: Any

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection (values come from JSON documents)."""
        return {"key": self.key, "left": self.left, "right": self.right}


@dataclass(frozen=True)
class MetadataCompare:
    """Outcome of :func:`compare_metadata`; frozen and JSON-safe."""

    left_kind: str | None
    right_kind: str | None
    same_kind: bool | None
    added_keys: tuple[str, ...] = ()
    removed_keys: tuple[str, ...] = ()
    changed: tuple[MetadataDetailChange, ...] = ()
    unchanged_keys: tuple[str, ...] = ()
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "metadata",
            "left_kind": self.left_kind,
            "right_kind": self.right_kind,
            "same_kind": self.same_kind,
            "added_keys": list(self.added_keys),
            "added_count": len(self.added_keys),
            "removed_keys": list(self.removed_keys),
            "removed_count": len(self.removed_keys),
            "changed": [change.to_dict() for change in self.changed],
            "changed_count": len(self.changed),
            "unchanged_keys": list(self.unchanged_keys),
            "unchanged_count": len(self.unchanged_keys),
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _metadata_kind(document: Mapping[str, Any], side: str, warnings: list[str]) -> str | None:
    """The ``kind`` string of a MetadataReport document, or ``None``."""
    kind = document.get("kind")
    if isinstance(kind, str) and kind.strip():
        return kind
    warnings.append(f"{side}: document has no usable 'kind' string")
    return None


def compare_metadata(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    max_detail_keys: int = DEFAULT_MAX_DETAIL_KEYS,
) -> MetadataCompare:
    """Diff two ``binmeta`` ``MetadataReport`` documents.

    ``kind`` is compared as a whole (``same_kind`` is ``None`` when either
    side lacks a usable kind string); the ``details`` dict is diffed at key
    level: keys present on one side only are added/removed, keys whose
    canonical-JSON values differ are listed as changed detail rows bounded
    at ``max_detail_keys``. Documents are the plain
    ``inspect_metadata(path).to_dict()`` payloads, so ``path`` fields (which
    always differ between two files) are deliberately ignored.

    Raises:
        AnalysisError: When a document is not a JSON object, has no
            ``details`` object, or the budget is out of range.
    """
    if max_detail_keys < 1 or max_detail_keys > MAX_COMPARE_DETAIL_KEYS:
        raise AnalysisError(
            f"max_detail_keys must be between 1 and {MAX_COMPARE_DETAIL_KEYS}"
        )
    warnings: list[str] = []
    left_map = _mapping_side(left, "left")
    right_map = _mapping_side(right, "right")
    left_kind = _metadata_kind(left_map, "left", warnings)
    right_kind = _metadata_kind(right_map, "right", warnings)
    if left_kind is None or right_kind is None:
        same_kind: bool | None = None
    else:
        same_kind = left_kind == right_kind

    left_details = left_map.get("details")
    if not isinstance(left_details, Mapping):
        raise AnalysisError("left: document has no 'details' object")
    right_details = right_map.get("details")
    if not isinstance(right_details, Mapping):
        raise AnalysisError("right: document has no 'details' object")
    left_keys = _string_keys(left_details, "left", warnings)
    right_keys = _string_keys(right_details, "right", warnings)

    added = sorted(set(right_keys) - set(left_keys))
    removed = sorted(set(left_keys) - set(right_keys))
    common = sorted(set(left_keys) & set(right_keys))
    changed_rows = [
        MetadataDetailChange(key=key, left=left_details[key], right=right_details[key])
        for key in common
        if _canonical_sha256(left_details[key]) != _canonical_sha256(right_details[key])
    ]
    unchanged = [
        key
        for key in common
        if _canonical_sha256(left_details[key]) == _canonical_sha256(right_details[key])
    ]
    changed_kept = _bounded("changed detail keys", changed_rows, max_detail_keys, warnings)
    identical = (
        not added
        and not removed
        and not changed_rows
        and same_kind is not False
    )
    evidence = Evidence(
        source=_EVIDENCE_METADATA_SOURCE,
        method="metadata_report_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"kinds {left_kind!r} vs {right_kind!r}; {len(changed_rows)} of "
            f"{len(common)} detail keys changed"
        ),
    )
    return MetadataCompare(
        left_kind=left_kind,
        right_kind=right_kind,
        same_kind=same_kind,
        added_keys=tuple(added),
        removed_keys=tuple(removed),
        changed=tuple(changed_kept),
        unchanged_keys=tuple(unchanged),
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_wasm -- two WASM modules via containers.inspect_wasm
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WasmSectionDelta:
    """One section id present on both sides, with per-side byte sizes."""

    id: int
    name: str
    left_size: int
    right_size: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "id": self.id,
            "name": self.name,
            "left_size": self.left_size,
            "right_size": self.right_size,
            "delta": self.right_size - self.left_size,
        }


@dataclass(frozen=True)
class WasmCompare:
    """Outcome of :func:`compare_wasm`; frozen and JSON-safe."""

    left_bytes: int
    right_bytes: int
    left_version: int
    right_version: int
    added_sections: tuple[str, ...] = ()
    removed_sections: tuple[str, ...] = ()
    section_deltas: tuple[WasmSectionDelta, ...] = ()
    imports_added: tuple[str, ...] = ()
    imports_removed: tuple[str, ...] = ()
    exports_added: tuple[str, ...] = ()
    exports_removed: tuple[str, ...] = ()
    size_delta: int = 0
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "wasm",
            "left_bytes": self.left_bytes,
            "right_bytes": self.right_bytes,
            "left_version": self.left_version,
            "right_version": self.right_version,
            "added_sections": list(self.added_sections),
            "added_count": len(self.added_sections),
            "removed_sections": list(self.removed_sections),
            "removed_count": len(self.removed_sections),
            "section_deltas": [delta.to_dict() for delta in self.section_deltas],
            "section_deltas_count": len(self.section_deltas),
            "imports_added": list(self.imports_added),
            "imports_removed": list(self.imports_removed),
            "exports_added": list(self.exports_added),
            "exports_removed": list(self.exports_removed),
            "size_delta": self.size_delta,
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _load_wasm(path: str | Path, side: str) -> tuple[bytes, WasmSummary]:
    """Read and inspect one WASM file, raising a typed error when it is not."""
    data = load_container_bytes(Path(path))
    summary = inspect_wasm(data)
    if summary is None:
        raise AnalysisError(f"{side}: {path} is not a WebAssembly module")
    return data, summary


def _bounded_set_diff(
    label: str, left: set[str], right: set[str], warnings: list[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Sorted added/removed string sets, each truncated with a warning."""
    added = _bounded(
        f"{label} (right-only)", sorted(right - left), DEFAULT_MAX_ROWS, warnings
    )
    removed = _bounded(
        f"{label} (left-only)", sorted(left - right), DEFAULT_MAX_ROWS, warnings
    )
    return tuple(added), tuple(removed)


def compare_wasm(left_path: str | Path, right_path: str | Path) -> WasmCompare:
    """Diff two WASM modules through :func:`containers.inspect_wasm`.

    Section sets are matched by section id (``added_sections`` and
    ``removed_sections`` render as ``id:name``); sections present on both
    sides yield a byte-size delta table. Import/export name diffs come from
    the bounded name lists the inspector extracts. The comparison is exact
    over the summaries; names beyond ``MAX_WASM_NAMES`` per vector are
    invisible to the diff (flagged in that side's inspector warnings,
    carried here).

    Raises:
        AnalysisError: When a file cannot be read, exceeds the container
            size ceiling, or has no WASM magic.
    """
    warnings: list[str] = []
    left_bytes, left = _load_wasm(left_path, "left")
    right_bytes, right = _load_wasm(right_path, "right")
    warnings.extend(f"left: {item}" for item in left.warnings)
    warnings.extend(f"right: {item}" for item in right.warnings)

    left_sections = {section.id: section for section in left.sections}
    right_sections = {section.id: section for section in right.sections}
    added_ids = sorted(set(right_sections) - set(left_sections))
    removed_ids = sorted(set(left_sections) - set(right_sections))
    added = [f"{sid}:{right_sections[sid].name}" for sid in added_ids]
    removed = [f"{sid}:{left_sections[sid].name}" for sid in removed_ids]
    deltas = [
        WasmSectionDelta(
            id=sid,
            name=left_sections[sid].name,
            left_size=left_sections[sid].size,
            right_size=right_sections[sid].size,
        )
        for sid in sorted(set(left_sections) & set(right_sections))
        if left_sections[sid].size != right_sections[sid].size
    ]
    imports_added, imports_removed = _bounded_set_diff(
        "import names", set(left.import_names), set(right.import_names), warnings
    )
    exports_added, exports_removed = _bounded_set_diff(
        "export names", set(left.export_names), set(right.export_names), warnings
    )
    identical = (
        left.version == right.version
        and not added_ids
        and not removed_ids
        and not deltas
        and not imports_added
        and not imports_removed
        and not exports_added
        and not exports_removed
        and len(left_bytes) == len(right_bytes)
    )
    evidence = Evidence(
        source=_EVIDENCE_WASM_SOURCE,
        method="wasm_summary_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(added_ids)} sections added, {len(removed_ids)} removed, "
            f"{len(deltas)} resized; exact set diff over inspector summaries"
        ),
    )
    return WasmCompare(
        left_bytes=len(left_bytes),
        right_bytes=len(right_bytes),
        left_version=left.version,
        right_version=right.version,
        added_sections=tuple(added),
        removed_sections=tuple(removed),
        section_deltas=tuple(deltas),
        imports_added=imports_added,
        imports_removed=imports_removed,
        exports_added=exports_added,
        exports_removed=exports_removed,
        size_delta=len(right_bytes) - len(left_bytes),
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_crash -- two ELF core dumps via crash_core.parse_core_dump
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegisterDelta:
    """One register present on both sides with its per-side hex values."""

    register: str
    left: str
    right: str
    changed: bool

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "register": self.register,
            "left": self.left,
            "right": self.right,
            "changed": self.changed,
        }


@dataclass(frozen=True)
class CrashCompare:
    """Outcome of :func:`compare_crash`; frozen and JSON-safe.

    ``same_crash_site`` is ``True`` when every decidable check passes; any
    decidable failure forces ``False`` at HIGH confidence (the mismatch is
    an exact observation), while undecidable inputs (missing signal note,
    unmapped faulting module) leave a ``True`` verdict at MEDIUM.
    """

    left_arch: str
    right_arch: str
    same_arch: bool
    left_signal: int | None
    right_signal: int | None
    same_signal: bool | None
    left_fault_module: str | None
    right_fault_module: str | None
    same_fault_module: bool | None
    fault_addr_same: bool | None
    rip_same: bool | None
    sp_same: bool | None
    rip_delta: int | None
    sp_delta: int | None
    register_deltas: tuple[RegisterDelta, ...] = ()
    same_crash_site: bool = False
    verdict_confidence: str = "low"
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with counts."""
        return {
            "what": "crash",
            "left_arch": self.left_arch,
            "right_arch": self.right_arch,
            "same_arch": self.same_arch,
            "left_signal": self.left_signal,
            "right_signal": self.right_signal,
            "same_signal": self.same_signal,
            "left_fault_module": self.left_fault_module,
            "right_fault_module": self.right_fault_module,
            "same_fault_module": self.same_fault_module,
            "fault_addr_same": self.fault_addr_same,
            "rip_same": self.rip_same,
            "sp_same": self.sp_same,
            "rip_delta": self.rip_delta,
            "sp_delta": self.sp_delta,
            "register_deltas": [delta.to_dict() for delta in self.register_deltas],
            "register_deltas_count": len(self.register_deltas),
            "same_crash_site": self.same_crash_site,
            "verdict_confidence": self.verdict_confidence,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


#: Register names tried, in order, for the instruction and stack pointers.
_IP_REGISTERS: tuple[str, ...] = ("rip", "eip", "pc")
_SP_REGISTERS: tuple[str, ...] = ("rsp", "esp", "sp")


def _pick_register(registers: dict[str, int], names: tuple[str, ...]) -> int | None:
    """First value of ``names`` present in ``registers``, or ``None``."""
    for name in names:
        if name in registers:
            return registers[name]
    return None


def _faulting_module(summary: CoreDumpSummary) -> str | None:
    """The mapped module containing the instruction pointer, if any."""
    ip = _pick_register(summary.registers, _IP_REGISTERS)
    if ip is None:
        return None
    for module in summary.mapped_modules:
        if module.start <= ip < module.end:
            return module.name
    return None


def _optional_equal(left: int | None, right: int | None) -> bool | None:
    """Tri-state equality: ``None`` when either side is unknown."""
    if left is None or right is None:
        return None
    return left == right


def _module_equal(left: str | None, right: str | None) -> bool | None:
    """Tri-state module equality: ``None`` only when both sides are unknown."""
    if left is None and right is None:
        return None
    if left is None or right is None:
        return False
    return left == right


def compare_crash(left_path: str | Path, right_path: str | Path) -> CrashCompare:
    """Decide whether two core dumps stopped at the same crash site.

    Both files are summarised by :func:`crash_core.parse_core_dump` (typed
    errors for non-core files). Checks: stop signal, faulting module (the
    mapped module containing the instruction pointer, ``None`` when the ip
    is unknown or unmapped), instruction-pointer and stack-pointer equality
    with numeric deltas, fault address, architecture, and a bounded
    register-delta table over the registers present on both sides.

    Returns:
        A frozen :class:`CrashCompare` whose ``same_crash_site`` verdict
        follows the class docstring's confidence rules.

    Raises:
        AnalysisError: When either file is missing, oversized, or not an
            ELF core dump.
    """
    warnings: list[str] = []
    left = parse_core_dump(Path(left_path))
    right = parse_core_dump(Path(right_path))

    left_ip = _pick_register(left.registers, _IP_REGISTERS)
    right_ip = _pick_register(right.registers, _IP_REGISTERS)
    left_sp = _pick_register(left.registers, _SP_REGISTERS)
    right_sp = _pick_register(right.registers, _SP_REGISTERS)
    left_module = _faulting_module(left)
    right_module = _faulting_module(right)

    same_signal = _optional_equal(left.signal, right.signal)
    same_module = _module_equal(left_module, right_module)
    rip_same = _optional_equal(left_ip, right_ip)
    sp_same = _optional_equal(left_sp, right_sp)

    common_registers = sorted(set(left.registers) & set(right.registers))
    delta_rows = [
        RegisterDelta(
            register=name,
            left=f"0x{left.registers[name]:x}",
            right=f"0x{right.registers[name]:x}",
            changed=left.registers[name] != right.registers[name],
        )
        for name in common_registers
    ]
    kept_rows = _bounded("register deltas", delta_rows, MAX_COMPARE_REGISTERS, warnings)

    checks = (same_signal, same_module, rip_same)
    failures = [value for value in checks if value is False]
    decidable = [value for value in checks if value is not None]
    if failures:
        same_site, confidence = False, Confidence.HIGH
    elif decidable and all(decidable):
        same_site, confidence = True, Confidence.HIGH
    else:
        same_site, confidence = True, Confidence.MEDIUM
    if left.arch != right.arch:
        warnings.append(f"architectures differ: {left.arch} vs {right.arch}")

    evidence = Evidence(
        source=_EVIDENCE_CRASH_SOURCE,
        method="core_site_diff",
        confidence=confidence,
        detail=(
            f"signal {left.signal} vs {right.signal}; fault module "
            f"{left_module} vs {right_module}"
        ),
    )
    return CrashCompare(
        left_arch=left.arch,
        right_arch=right.arch,
        same_arch=left.arch == right.arch,
        left_signal=left.signal,
        right_signal=right.signal,
        same_signal=same_signal,
        left_fault_module=left_module,
        right_fault_module=right_module,
        same_fault_module=same_module,
        fault_addr_same=_optional_equal(left.fault_addr, right.fault_addr),
        rip_same=rip_same,
        sp_same=sp_same,
        rip_delta=None if left_ip is None or right_ip is None else right_ip - left_ip,
        sp_delta=None if left_sp is None or right_sp is None else right_sp - left_sp,
        register_deltas=tuple(kept_rows),
        same_crash_site=same_site,
        verdict_confidence=confidence.value,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_sessions -- two session databases via sqlite_view + ro/immutable SQL
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionsCompare:
    """Outcome of :func:`compare_sessions`; frozen and JSON-safe.

    Session identifiers are local to each database, so address membership
    is compared across all sessions of a database, not per session id.
    """

    left_sessions: int | None
    right_sessions: int | None
    left_annotations: int
    right_annotations: int
    annotation_delta: int
    addresses_only_left: tuple[str, ...] = ()
    addresses_only_right: tuple[str, ...] = ()
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with counts."""
        return {
            "what": "sessions",
            "left_sessions": self.left_sessions,
            "right_sessions": self.right_sessions,
            "left_annotations": self.left_annotations,
            "right_annotations": self.right_annotations,
            "annotation_delta": self.annotation_delta,
            "addresses_only_left": list(self.addresses_only_left),
            "addresses_only_left_count": len(self.addresses_only_left),
            "addresses_only_right": list(self.addresses_only_right),
            "addresses_only_right_count": len(self.addresses_only_right),
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _open_session_db(candidate: Path) -> sqlite3.Connection:
    """Open a session database through the ``mode=ro&immutable=1`` URI.

    Mirrors :func:`codevanta.analysis.sqlite_view._open_readonly`; kept
    local because that helper is private.
    """
    uri = f"file:{urllib.request.pathname2url(str(candidate))}?mode=ro&immutable=1"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise AnalysisError(f"cannot open database {str(candidate)!r}: {exc}") from exc


def _session_db_names(path: Path, side: str) -> tuple[list[str], sqlite3.Connection]:
    """Validate ``path`` as a session database and return its table names.

    Validation goes through :func:`sqlite_view.inspect_sqlite` (existence,
    magic, size ceiling); the annotations table is required. The returned
    read-only connection is left open for the caller's SELECTs.
    """
    summary = inspect_sqlite(path)
    names = [table.name for table in summary.tables]
    if "annotations" not in names:
        raise AnalysisError(
            f"{side}: {path} is not a CODEVANTA session database "
            "(no 'annotations' table)"
        )
    return names, _open_session_db(path)


def _annotation_addresses(path: Path, side: str) -> set[int]:
    """Every annotated address in the database (across all sessions)."""
    _, connection = _session_db_names(path, side)
    try:
        rows = connection.execute("SELECT address FROM annotations").fetchall()
    except sqlite3.Error as exc:
        raise AnalysisError(f"{side}: cannot read annotations of {path}: {exc}") from exc
    finally:
        connection.close()
    return {int(row[0]) for row in rows}


def _session_count(path: Path, side: str, warnings: list[str]) -> int | None:
    """Number of rows in the ``sessions`` table, ``None`` when absent."""
    connection = _open_session_db(path)
    try:
        row = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()
    except sqlite3.Error:
        warnings.append(f"{side}: database has no readable 'sessions' table")
        return None
    finally:
        connection.close()
    return int(row[0] if row else 0)


def _address_labels(addresses: set[int]) -> list[str]:
    """Render addresses as sorted ``0x`` strings."""
    return [f"0x{address:x}" for address in sorted(addresses)]


def compare_sessions(
    left_path: str | Path,
    right_path: str | Path,
    *,
    max_addresses: int = DEFAULT_MAX_ROWS,
) -> SessionsCompare:
    """Diff two CODEVANTA session databases.

    Both files are validated through :func:`sqlite_view.inspect_sqlite`
    (read-only, immutable mode; the ``annotations`` table must exist).
    Reports the annotated-address counts per side with their delta, the
    saved session counts, and the annotated addresses found on only one
    side, bounded at ``max_addresses`` per delta with truncation warnings.
    Nothing is written: the databases are opened through
    ``mode=ro&immutable=1`` connections only.

    Raises:
        AnalysisError: When a path is missing, is not a SQLite 3 file, is
            over the size ceiling, or lacks the ``annotations`` table.
    """
    if max_addresses < 1 or max_addresses > MAX_COMPARE_ROWS:
        raise AnalysisError(f"max_addresses must be between 1 and {MAX_COMPARE_ROWS}")
    warnings: list[str] = []
    left_path = Path(left_path)
    right_path = Path(right_path)
    left_addresses = _annotation_addresses(left_path, "left")
    right_addresses = _annotation_addresses(right_path, "right")
    left_count = _session_count(left_path, "left", warnings)
    right_count = _session_count(right_path, "right", warnings)
    only_left = _bounded(
        "addresses only in left",
        _address_labels(left_addresses - right_addresses),
        max_addresses,
        warnings,
    )
    only_right = _bounded(
        "addresses only in right",
        _address_labels(right_addresses - left_addresses),
        max_addresses,
        warnings,
    )
    identical = len(left_addresses) == len(right_addresses) and (
        left_addresses == right_addresses
    )
    evidence = Evidence(
        source=_EVIDENCE_SESSIONS_SOURCE,
        method="session_annotation_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(left_addresses)} vs {len(right_addresses)} annotated "
            "addresses; ro&immutable connections, no writes"
        ),
    )
    return SessionsCompare(
        left_sessions=left_count,
        right_sessions=right_count,
        left_annotations=len(left_addresses),
        right_annotations=len(right_addresses),
        annotation_delta=len(right_addresses) - len(left_addresses),
        addresses_only_left=tuple(only_left),
        addresses_only_right=tuple(only_right),
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_nav -- two session databases via nav.NavStore
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BookmarkMove:
    """A bookmark name present on both sides but pinned at new addresses."""

    name: str
    left_address: str
    right_address: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "name": self.name,
            "left_address": self.left_address,
            "right_address": self.right_address,
        }


@dataclass(frozen=True)
class CommentChange:
    """A comment address present on both sides with different text."""

    address: str
    left_text: str
    right_text: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "address": self.address,
            "left_text": self.left_text,
            "right_text": self.right_text,
        }


@dataclass(frozen=True)
class NavCompare:
    """Outcome of :func:`compare_nav`; frozen and JSON-safe."""

    session_id: str
    left_bookmarks: int
    right_bookmarks: int
    left_comments: int
    right_comments: int
    bookmarks_added: tuple[str, ...] = ()
    bookmarks_removed: tuple[str, ...] = ()
    bookmarks_moved: tuple[BookmarkMove, ...] = ()
    comments_added: tuple[str, ...] = ()
    comments_removed: tuple[str, ...] = ()
    comments_changed: tuple[CommentChange, ...] = ()
    cursor_left: str | None = None
    cursor_right: str | None = None
    cursor_same: bool | None = None
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "nav",
            "session_id": self.session_id,
            "left_bookmarks": self.left_bookmarks,
            "right_bookmarks": self.right_bookmarks,
            "left_comments": self.left_comments,
            "right_comments": self.right_comments,
            "bookmarks_added": list(self.bookmarks_added),
            "bookmarks_added_count": len(self.bookmarks_added),
            "bookmarks_removed": list(self.bookmarks_removed),
            "bookmarks_removed_count": len(self.bookmarks_removed),
            "bookmarks_moved": [move.to_dict() for move in self.bookmarks_moved],
            "bookmarks_moved_count": len(self.bookmarks_moved),
            "comments_added": list(self.comments_added),
            "comments_added_count": len(self.comments_added),
            "comments_removed": list(self.comments_removed),
            "comments_removed_count": len(self.comments_removed),
            "comments_changed": [change.to_dict() for change in self.comments_changed],
            "comments_changed_count": len(self.comments_changed),
            "cursor_left": self.cursor_left,
            "cursor_right": self.cursor_right,
            "cursor_same": self.cursor_same,
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _latest_session_id(db_path: Path) -> str:
    """Newest saved session id in ``db_path`` (typed error when none)."""
    connection = _open_session_db(db_path)
    try:
        row = connection.execute(
            "SELECT session_id FROM sessions "
            "ORDER BY created_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise AnalysisError(f"cannot list sessions in {db_path}: {exc}") from exc
    finally:
        connection.close()
    if row is None:
        raise AnalysisError(
            f"{db_path} has no saved sessions; "
            "save one first with `codevanta session save`"
        )
    return str(row[0])


def compare_nav(
    left_path: str | Path,
    right_path: str | Path,
    *,
    session_id: str | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> NavCompare:
    """Diff navigation state of two session databases via
    :class:`codevanta.analysis.nav.NavStore`.

    The same ``session_id`` is read from both databases; ``None`` picks the
    newest saved session in each. Bookmarks are matched by name (ambiguous
    names duplicated on either side are skipped with a warning, mirroring
    :func:`compare_inventories`), so a name can be added, removed or
    *moved* (same name, different address). Comments are matched by address
    (unique per session) so their text can change. The cursor is compared
    as a tri-state: both ``None`` counts as the same.

    Raises:
        AnalysisError: When a database has no saved session, when the
            requested ``session_id`` is missing on either side, or when the
            budget is out of range.
    """
    if max_rows < 1 or max_rows > MAX_COMPARE_ROWS:
        raise AnalysisError(f"max_rows must be between 1 and {MAX_COMPARE_ROWS}")
    warnings: list[str] = []
    left_path = Path(left_path)
    right_path = Path(right_path)
    if session_id is not None:
        sid_left = sid_right = session_id
        reported_sid = session_id
    else:
        sid_left = _latest_session_id(left_path)
        sid_right = _latest_session_id(right_path)
        reported_sid = sid_left
        if sid_right != sid_left:
            warnings.append(
                f"right database has no session {sid_left}; compared its "
                f"newest session {sid_right}"
            )
    with NavStore(left_path) as left_store, NavStore(right_path) as right_store:
        left_bookmarks = left_store.bookmarks(sid_left)
        right_bookmarks = right_store.bookmarks(sid_right)
        left_comments = left_store.comments(sid_left)
        right_comments = right_store.comments(sid_right)
        left_cursor = left_store.cursor(sid_left)
        right_cursor = right_store.cursor(sid_right)

    left_by_name: dict[str, list[int]] = {}
    for bookmark in left_bookmarks:
        left_by_name.setdefault(bookmark.name, []).append(bookmark.address)
    right_by_name: dict[str, list[int]] = {}
    for bookmark in right_bookmarks:
        right_by_name.setdefault(bookmark.name, []).append(bookmark.address)
    ambiguous = {
        name
        for name in set(left_by_name) | set(right_by_name)
        if len(left_by_name.get(name, [])) > 1 or len(right_by_name.get(name, [])) > 1
    }
    for name in sorted(ambiguous):
        warnings.append(f"bookmark name {name!r} is duplicated on a side; skipped")
    added_names = sorted(
        name
        for name in set(right_by_name) - set(left_by_name)
        if name not in ambiguous
    )
    removed_names = sorted(
        name
        for name in set(left_by_name) - set(right_by_name)
        if name not in ambiguous
    )
    moved_rows = [
        BookmarkMove(
            name=name,
            left_address=f"0x{left_by_name[name][0]:x}",
            right_address=f"0x{right_by_name[name][0]:x}",
        )
        for name in sorted(set(left_by_name) & set(right_by_name))
        if name not in ambiguous and left_by_name[name][0] != right_by_name[name][0]
    ]
    bookmarks_added = _bounded(
        "bookmarks only in right", added_names, max_rows, warnings
    )
    bookmarks_removed = _bounded(
        "bookmarks only in left", removed_names, max_rows, warnings
    )
    bookmarks_moved = _bounded("moved bookmarks", moved_rows, max_rows, warnings)

    left_comment_map = {comment.address: comment.text for comment in left_comments}
    right_comment_map = {comment.address: comment.text for comment in right_comments}
    comments_added = _bounded(
        "comments only in right",
        _address_labels(set(right_comment_map) - set(left_comment_map)),
        max_rows,
        warnings,
    )
    comments_removed = _bounded(
        "comments only in left",
        _address_labels(set(left_comment_map) - set(right_comment_map)),
        max_rows,
        warnings,
    )
    changed_rows = [
        CommentChange(
            address=f"0x{address:x}",
            left_text=left_comment_map[address],
            right_text=right_comment_map[address],
        )
        for address in sorted(set(left_comment_map) & set(right_comment_map))
        if left_comment_map[address] != right_comment_map[address]
    ]
    comments_changed = _bounded("changed comments", changed_rows, max_rows, warnings)

    if left_cursor is None and right_cursor is None:
        cursor_same: bool | None = True
    elif left_cursor is None or right_cursor is None:
        cursor_same = False
    else:
        cursor_same = left_cursor.address == right_cursor.address
    identical = (
        not bookmarks_added
        and not bookmarks_removed
        and not bookmarks_moved
        and not comments_added
        and not comments_removed
        and not comments_changed
        and cursor_same is not False
    )
    evidence = Evidence(
        source=_EVIDENCE_NAV_SOURCE,
        method="session_nav_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"session {reported_sid}: {len(left_bookmarks)} vs {len(right_bookmarks)} "
            f"bookmarks, {len(left_comments)} vs {len(right_comments)} comments"
        ),
    )
    return NavCompare(
        session_id=reported_sid,
        left_bookmarks=len(left_bookmarks),
        right_bookmarks=len(right_bookmarks),
        left_comments=len(left_comments),
        right_comments=len(right_comments),
        bookmarks_added=tuple(bookmarks_added),
        bookmarks_removed=tuple(bookmarks_removed),
        bookmarks_moved=tuple(bookmarks_moved),
        comments_added=tuple(comments_added),
        comments_removed=tuple(comments_removed),
        comments_changed=tuple(comments_changed),
        cursor_left=None if left_cursor is None else left_cursor.to_dict()["address"],
        cursor_right=None if right_cursor is None else right_cursor.to_dict()["address"],
        cursor_same=cursor_same,
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_firmware -- two firmware magic scans via containers.scan_magics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FirmwareCompare:
    """Outcome of :func:`compare_firmware`; frozen and JSON-safe."""

    left_bytes: int
    right_bytes: int
    left_hits: int
    right_hits: int
    hits_added: tuple[dict[str, Any], ...] = ()
    hits_removed: tuple[dict[str, Any], ...] = ()
    unchanged_hit_count: int = 0
    size_delta: int = 0
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "firmware",
            "left_bytes": self.left_bytes,
            "right_bytes": self.right_bytes,
            "left_hits": self.left_hits,
            "right_hits": self.right_hits,
            "hits_added": [dict(hit) for hit in self.hits_added],
            "hits_added_count": len(self.hits_added),
            "hits_removed": [dict(hit) for hit in self.hits_removed],
            "hits_removed_count": len(self.hits_removed),
            "unchanged_hit_count": self.unchanged_hit_count,
            "size_delta": self.size_delta,
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _magic_hits(path: str | Path) -> tuple[int, dict[tuple[int, str], str]]:
    """File size and ``{(offset, kind): confidence}`` map of one scan."""
    data = load_container_bytes(Path(path))
    summary = scan_magics(data)
    hits: dict[tuple[int, str], str] = {}
    if summary is not None:
        for hit in summary.hits:
            hits[(hit.offset, hit.kind)] = hit.confidence
    return len(data), hits


def compare_firmware(left_path: str | Path, right_path: str | Path) -> FirmwareCompare:
    """Diff two firmware images' magic-scan results.

    Both files are swept by :func:`containers.scan_magics`; a scan with no
    hits (``scan_magics`` returns ``None``) is treated as an empty hit set,
    never an error. Hits are keyed by ``(offset, kind)``, so
    ``hits_added``/``hits_removed`` report exactly which signature matches
    appeared or disappeared, bounded at :data:`DEFAULT_MAX_ROWS` per side.
    The membership diff itself is exact, but every hit inherits the
    heuristic (LOW/MEDIUM) confidence of the underlying signature scan, so
    the evidence record is MEDIUM: a match appearing may be coincidence,
    not a new embedded image.

    Raises:
        AnalysisError: When a file cannot be read or exceeds the container
            size ceiling.
    """
    warnings: list[str] = []
    left_size, left_hits = _magic_hits(left_path)
    right_size, right_hits = _magic_hits(right_path)
    added_keys = sorted(set(right_hits) - set(left_hits))
    removed_keys = sorted(set(left_hits) - set(right_hits))
    hits_added = _bounded(
        "hits only in right",
        [{"offset": offset, "kind": kind} for offset, kind in added_keys],
        DEFAULT_MAX_ROWS,
        warnings,
    )
    hits_removed = _bounded(
        "hits only in left",
        [{"offset": offset, "kind": kind} for offset, kind in removed_keys],
        DEFAULT_MAX_ROWS,
        warnings,
    )
    identical = not added_keys and not removed_keys
    evidence = Evidence(
        source=_EVIDENCE_FIRMWARE_SOURCE,
        method="firmware_magic_diff",
        confidence=Confidence.MEDIUM,
        detail=(
            f"{len(added_keys)} hits appeared, {len(removed_keys)} disappeared; "
            "membership diff is exact but per-hit provenance is heuristic triage"
        ),
    )
    return FirmwareCompare(
        left_bytes=left_size,
        right_bytes=right_size,
        left_hits=len(left_hits),
        right_hits=len(right_hits),
        hits_added=tuple(dict(row) for row in hits_added),
        hits_removed=tuple(dict(row) for row in hits_removed),
        unchanged_hit_count=len(set(left_hits) & set(right_hits)),
        size_delta=right_size - left_size,
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_screenshots -- two captured PNG screenshots via pixel_diff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreenshotCompare:
    """Outcome of :func:`compare_screenshots`; frozen and JSON-safe.

    Reuses the :class:`~codevanta.analysis.png_diff.ScreenshotDiff` pixel
    metrics verbatim and adds the registry-level evidence record.
    """

    diff: ScreenshotDiff
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as ``what: screenshots`` plus the embedded pixel diff."""
        return {
            "what": "screenshots",
            **self.diff.to_dict(),
            "evidence": dict(self.evidence),
        }


def compare_screenshots(
    left_path: str | Path, right_path: str | Path
) -> ScreenshotCompare:
    """Diff two captured screenshots through :func:`png_diff.pixel_diff`.

    Both PNG files are decoded locally (8-bit grayscale/RGB/RGBA,
    non-interlaced) and compared pixel by pixel: the changed-pixel ratio
    drives the ``identical`` (ratio ``0.0``) / ``minor`` (``< 0.01``) /
    ``major`` verdict, per-channel mean deltas say *where* the pixels
    moved, and images with different dimensions are ``major`` with a note.
    Exact local pixel metrics, no OCR, no rendering -- hence ``HIGH``
    confidence.

    Raises:
        AnalysisError: When either file cannot be read or decoded.
    """
    diff = pixel_diff(left_path, right_path)
    evidence = Evidence(
        source=_EVIDENCE_SCREENSHOT_SOURCE,
        method="screenshot_file_diff",
        confidence=Confidence.HIGH,
        detail=(
            "both PNGs decoded with the local minimal decoder and compared "
            "pixel-by-pixel; exact metrics, no OCR or rendering involved"
        ),
    )
    return ScreenshotCompare(
        diff=diff,
        warnings=diff.warnings,
        evidence=evidence.to_dict(),
    )


# ---------------------------------------------------------------------------
# compare_har -- two HAR capture files via analysis.har_capture
# ---------------------------------------------------------------------------


def _load_har(path: str | Path) -> Any:
    """Load one HAR summary through the sibling ``har_capture`` module.

    The import is deliberately inside the function and typed: the capture
    module ships in its own lane, and this comparator must fail with a
    clear :class:`AnalysisError` -- never an ``ImportError`` traceback --
    when it is absent.
    """
    try:
        from codevanta.analysis.har_capture import load_har
    except ImportError as exc:  # pragma: no cover - depends on lane merge order
        raise AnalysisError(
            "HAR comparison needs codevanta.analysis.har_capture, which is "
            "not available in this build"
        ) from exc
    return load_har(Path(path))


def _url_path(url: str) -> str:
    """Path portion of a request URL (scheme/host and query dropped).

    A URL without a path resolves to ``/`` so membership diffs stay stable;
    anything ``urlsplit`` cannot treat as a URL keeps its pathless form.
    """
    split = urllib.parse.urlsplit(url)
    return split.path or "/"


@dataclass(frozen=True)
class HarMethodDelta:
    """One HTTP method's request count, per side, with the delta in ``to_dict``."""

    method: str
    left: int
    right: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "method": self.method,
            "left": self.left,
            "right": self.right,
            "delta": self.right - self.left,
        }


@dataclass(frozen=True)
class HarStatusChange:
    """One (method, path) request whose status-code set differs."""

    method: str
    path: str
    left_statuses: tuple[int, ...]
    right_statuses: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection."""
        return {
            "method": self.method,
            "path": self.path,
            "left_statuses": list(self.left_statuses),
            "right_statuses": list(self.right_statuses),
        }


@dataclass(frozen=True)
class HarCompare:
    """Outcome of :func:`compare_har`; frozen and JSON-safe.

    ``left_entries``/``right_entries`` are the walked entry counts of both
    captures; the path/status/method deltas are computed over the rows the
    capture module lists per side (``left_listed``/``right_listed`` state
    how many that was, so a truncated capture is never mistaken for an
    empty one). ``verdict`` is ``identical`` only when no entry delta, no
    one-sided path, no status change and no method delta exists -- timing
    deltas never affect it.
    """

    left_entries: int
    right_entries: int
    paths_added: tuple[str, ...] = ()
    paths_removed: tuple[str, ...] = ()
    status_changes: tuple[HarStatusChange, ...] = ()
    status_change_count: int = 0
    method_deltas: tuple[HarMethodDelta, ...] = ()
    left_listed: int = 0
    right_listed: int = 0
    time_delta_ms: float = 0.0
    verdict: str = "identical"
    identical: bool = False
    warnings: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a JSON-safe dict with per-list counts."""
        return {
            "what": "har",
            "left_entries": self.left_entries,
            "right_entries": self.right_entries,
            "entry_delta": self.right_entries - self.left_entries,
            "paths_added": list(self.paths_added),
            "paths_added_count": len(self.paths_added),
            "paths_removed": list(self.paths_removed),
            "paths_removed_count": len(self.paths_removed),
            "status_changes": [change.to_dict() for change in self.status_changes],
            "status_change_count": self.status_change_count,
            "method_deltas": [delta.to_dict() for delta in self.method_deltas],
            "left_listed": self.left_listed,
            "right_listed": self.right_listed,
            "time_delta_ms": self.time_delta_ms,
            "verdict": self.verdict,
            "identical": self.identical,
            "warnings": list(self.warnings),
            "evidence": dict(self.evidence),
        }


def _har_side_index(summary: Any, side: str, warnings: list[str]) -> Any:
    """Side-labelled sanity view of one ``HarCaptureSummary``.

    Returns the summary after checking it has the documented ``rows`` and
    ``entry_count`` fields, and records a warning when the capture module
    truncated its entry walk (rows listed < entries walked).
    """
    rows = getattr(summary, "rows", None)
    entry_count = getattr(summary, "entry_count", None)
    if not isinstance(rows, tuple) or not isinstance(entry_count, int):
        raise AnalysisError(f"{side}: har_capture returned no HarCaptureSummary shape")
    truncated = bool(getattr(summary, "truncated", False))
    if truncated or len(rows) < entry_count:
        warnings.append(
            f"{side}: capture lists {len(rows)} of {entry_count} walked "
            "entries; path/status/method diffs cover listed rows only"
        )
    return summary


def _har_statuses_by_request(
    summary: Any,
) -> tuple[set[str], dict[tuple[str, str], tuple[int, ...]]]:
    """``(method, path)`` request keys and their sorted status codes.

    The path set drives the added/removed diff; the per-request status
    tuples drive the status-change diff. Request keys are uppercase method
    plus queryless URL path.
    """
    paths: set[str] = set()
    statuses: dict[tuple[str, str], set[int]] = {}
    for row in summary.rows:
        method = str(getattr(row, "method", "")).upper()
        path = _url_path(str(getattr(row, "url", "")))
        paths.add(path)
        statuses.setdefault((method, path), set()).add(int(getattr(row, "status", 0)))
    return paths, {key: tuple(sorted(codes)) for key, codes in statuses.items()}


def compare_har(
    left_path: str | Path,
    right_path: str | Path,
    *,
    max_paths: int = DEFAULT_MAX_HAR_PATHS,
) -> HarCompare:
    """Diff two HAR capture files through :mod:`codevanta.analysis.har_capture`.

    Both files are summarised by the capture module, then compared exactly
    over those summaries: the entry-count delta, the queryless URL paths
    that appear on only one side (bounded by ``max_paths``, ``1`` ..
    :data:`MAX_COMPARE_HAR_PATHS`, truncation warned), the ``(method,
    path)`` requests whose status-code set changed, and the per-method
    request-count histogram deltas. Total-time deltas are reported but
    never affect ``identical`` -- timing differs between captures by
    nature. The membership diff is exact over parsed entries, so the
    evidence record is ``HIGH``.

    Raises:
        AnalysisError: When the budget is out of range, a file cannot be
            read, or either HAR is malformed (typed errors from the
            capture module pass through).
    """
    if max_paths < 1 or max_paths > MAX_COMPARE_HAR_PATHS:
        raise AnalysisError(f"max_paths must be between 1 and {MAX_COMPARE_HAR_PATHS}")
    warnings: list[str] = []
    left = _har_side_index(_load_har(left_path), "left", warnings)
    right = _har_side_index(_load_har(right_path), "right", warnings)
    left_paths, left_statuses = _har_statuses_by_request(left)
    right_paths, right_statuses = _har_statuses_by_request(right)

    added = _bounded(
        "paths (right-only)", sorted(right_paths - left_paths), max_paths, warnings
    )
    removed = _bounded(
        "paths (left-only)", sorted(left_paths - right_paths), max_paths, warnings
    )
    changed_rows = [
        HarStatusChange(
            method=method,
            path=path,
            left_statuses=left_statuses[(method, path)],
            right_statuses=right_statuses[(method, path)],
        )
        for method, path in sorted(set(left_statuses) & set(right_statuses))
        if left_statuses[(method, path)] != right_statuses[(method, path)]
    ]
    changed_kept = _bounded("status changes", changed_rows, max_paths, warnings)

    left_methods = Counter(str(getattr(row, "method", "")).upper() for row in left.rows)
    right_methods = Counter(str(getattr(row, "method", "")).upper() for row in right.rows)
    method_deltas = [
        HarMethodDelta(
            method=method, left=left_methods[method], right=right_methods[method]
        )
        for method in sorted(set(left_methods) | set(right_methods))
        if left_methods[method] != right_methods[method]
    ]

    identical = (
        left.entry_count == right.entry_count
        and not added
        and not removed
        and not changed_rows
        and not method_deltas
    )
    evidence = Evidence(
        source=_EVIDENCE_HAR_SOURCE,
        method="har_summary_diff",
        confidence=Confidence.HIGH,
        detail=(
            f"{right.entry_count - left.entry_count:+d} entry delta, "
            f"{len(added)} paths added, {len(removed)} removed, "
            f"{len(changed_rows)} status changes, {len(method_deltas)} "
            "method count deltas; exact diff over parsed HAR entries"
        ),
    )
    return HarCompare(
        left_entries=left.entry_count,
        right_entries=right.entry_count,
        paths_added=tuple(added),
        paths_removed=tuple(removed),
        status_changes=tuple(changed_kept),
        status_change_count=len(changed_rows),
        method_deltas=tuple(method_deltas),
        left_listed=len(left.rows),
        right_listed=len(right.rows),
        time_delta_ms=round(
            float(getattr(right, "total_time_ms", 0.0))
            - float(getattr(left, "total_time_ms", 0.0)),
            3,
        ),
        verdict="identical" if identical else "changed",
        identical=identical,
        warnings=_dedupe_warnings(warnings),
        evidence=evidence.to_dict(),
    )


# --- compare_har appended below ---


def compare_artifacts(
    what: str,
    left: str | Path,
    right: str | Path,
    *,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_strings: int = DEFAULT_MAX_STRINGS,
    max_changed_sections: int = DEFAULT_MAX_CHANGED_SECTIONS,
    max_detail_keys: int = DEFAULT_MAX_DETAIL_KEYS,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> Any:
    """Run one registered comparison from :data:`COMPARE_WHATS`.

    This is the single dispatch point shared by the CLI and the MCP tool:
    the JSON-backed kinds (``functions``, ``strings``, ``bundles``,
    ``reports``, ``metadata``) load their documents from the two paths, the
    path-backed kinds (``wasm``, ``crash``, ``sessions``, ``nav``,
    ``firmware``, ``screenshots``, ``har``) hand the paths straight to
    their typed loaders. Bundles
    must be evidence-bundle documents; reports unwrap an evidence bundle to
    its ``report`` entry automatically.

    Returns:
        The frozen result object of the selected comparator; every member
        has a JSON-safe ``to_dict``.

    Raises:
        AnalysisError: For an unknown ``what`` or any comparator input
            error.
    """
    if what not in COMPARE_WHATS:
        raise AnalysisError(
            f"unknown --what {what!r}; expected one of {', '.join(COMPARE_WHATS)}"
        )
    if what == "functions":
        return compare_inventories(
            load_report_payload(left),
            load_report_payload(right),
            max_functions=max_functions,
        )
    if what == "strings":
        return compare_strings(
            load_report_payload(left),
            load_report_payload(right),
            max_strings=max_strings,
        )
    if what == "bundles":
        left_document = load_document(left)
        right_document = load_document(right)
        if not is_bundle_document(left_document):
            raise AnalysisError(f"{left} is not an evidence-bundle document")
        if not is_bundle_document(right_document):
            raise AnalysisError(f"{right} is not an evidence-bundle document")
        return compare_bundles(left_document, right_document)
    if what == "reports":
        return compare_reports(
            load_report_payload(left),
            load_report_payload(right),
            max_changed_sections=max_changed_sections,
        )
    if what == "metadata":
        return compare_metadata(
            load_document(left),
            load_document(right),
            max_detail_keys=max_detail_keys,
        )
    if what == "wasm":
        return compare_wasm(left, right)
    if what == "crash":
        return compare_crash(left, right)
    if what == "sessions":
        return compare_sessions(left, right, max_addresses=max_rows)
    if what == "nav":
        return compare_nav(left, right, max_rows=max_rows)
    if what == "screenshots":
        return compare_screenshots(left, right)
    if what == "har":
        return compare_har(left, right)
    return compare_firmware(left, right)

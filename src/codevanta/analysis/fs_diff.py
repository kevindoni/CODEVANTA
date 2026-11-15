"""Filesystem snapshot + diff: verify what an application DOES to the tree.

Two plain functions cover the before/after workflow. ``snapshot_tree``
recursively walks a directory (``os.walk`` with ``followlinks=False``) and
records every regular file (relative POSIX path, size, sha256 of the content
for files within the hash budget), every directory and every symlink (target
text only, never followed). ``diff_snapshots`` compares two snapshots by
relative path + content fingerprint and classifies each path as created,
deleted, modified or unchanged, with an ``identical``/``changed`` verdict.

Bounds
------
Walking is bounded (:data:`MAX_ENTRIES` entries, :data:`MAX_TOTAL_BYTES`
hashed bytes, :data:`DEFAULT_MAX_HASH_BYTES` per file -- bigger files are
recorded size-only with ``hashed: false``); everything past a bound is a
``truncated`` flag plus warning. Diff lists are bounded by ``max_lists``.
Symlink targets are clipped to :data:`MAX_SYMLINK_TARGET_CHARS`. Snapshots
carry no timestamps: the same tree snapshots to a byte-identical manifest.
The only exception raised is :class:`~codevanta.core.report.AnalysisError`.
Nothing is fetched or executed.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_HASH_BYTES",
    "EVIDENCE_DIFF_SOURCE",
    "EVIDENCE_SNAPSHOT_SOURCE",
    "FsDiff",
    "FsEntry",
    "FsSnapshot",
    "MAX_ENTRIES",
    "MAX_HASH_CHUNK",
    "MAX_SYMLINK_TARGET_CHARS",
    "MAX_TOTAL_BYTES",
    "ModifiedRecord",
    "diff_snapshots",
    "load_snapshot",
    "snapshot_tree",
]

#: Entries (files + dirs + symlinks) collected per snapshot before the rest
#: are skipped (truncated flag + warning).
MAX_ENTRIES = 2048

#: Files above this size are recorded size-only (``hashed: false``), never read.
DEFAULT_MAX_HASH_BYTES = 8_388_608

#: Hard ceiling on content bytes one snapshot will read for hashing.
MAX_TOTAL_BYTES = 256 * 1024 * 1024

#: Streaming chunk size for sha256 -- content never sits in memory whole.
MAX_HASH_CHUNK = 1024 * 1024

#: Longest symlink target recorded; longer targets are clipped.
MAX_SYMLINK_TARGET_CHARS = 256

#: Shared evidence ``source`` for snapshots.
EVIDENCE_SNAPSHOT_SOURCE = "fs.snapshot"

#: Shared evidence ``source`` for diffs.
EVIDENCE_DIFF_SOURCE = "fs.diff"

_ENTRY_KINDS = ("file", "dir", "symlink")


@dataclass(frozen=True)
class FsEntry:
    """One recorded tree member (relative POSIX path, no timestamps)."""

    kind: str
    path: str
    size: int
    sha256: str | None = None
    hashed: bool = False
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "hashed": self.hashed,
            "target": self.target,
        }


@dataclass(frozen=True)
class FsSnapshot:
    """Bounded, deterministic manifest of one directory tree."""

    root: str
    entries: tuple[FsEntry, ...]
    file_count: int
    dir_count: int
    symlink_count: int
    hashed_count: int
    total_bytes: int
    entries_truncated: bool
    bytes_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "entries": [entry.to_dict() for entry in self.entries],
            "entry_count": len(self.entries),
            "counts": {
                "files": self.file_count,
                "dirs": self.dir_count,
                "symlinks": self.symlink_count,
            },
            "hashed_count": self.hashed_count,
            "total_bytes": self.total_bytes,
            "truncated": {
                "entries": self.entries_truncated,
                "bytes": self.bytes_truncated,
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> FsSnapshot:
        """Coerce a JSON manifest back into a snapshot (typed errors)."""
        if not isinstance(payload, dict):
            raise AnalysisError("malformed snapshot: not a JSON object")
        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list):
            raise AnalysisError("malformed snapshot: missing 'entries' list")
        entries: list[FsEntry] = []
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
                raise AnalysisError(
                    f"malformed snapshot: entry {index} has no string 'path'"
                )
            kind = raw.get("kind", "file")
            if kind not in _ENTRY_KINDS:
                raise AnalysisError(
                    f"malformed snapshot: entry {index} has unknown kind {kind!r}"
                )
            size = raw.get("size", 0)
            sha256 = raw.get("sha256")
            hashed = raw.get("hashed", bool(sha256))
            if isinstance(size, bool) or not isinstance(size, int):
                raise AnalysisError(
                    f"malformed snapshot: entry {index} has non-integer size"
                )
            target = raw.get("target")
            if target is not None and not isinstance(target, str):
                raise AnalysisError(
                    f"malformed snapshot: entry {index} has non-string target"
                )
            entries.append(
                FsEntry(
                    kind=kind,
                    path=raw["path"],
                    size=size,
                    sha256=sha256 if isinstance(sha256, str) else None,
                    hashed=bool(hashed),
                    target=target,
                )
            )
        counts = payload.get("counts")
        truncated = payload.get("truncated")
        if not isinstance(counts, dict):
            counts = {}
        if not isinstance(truncated, dict):
            truncated = {}
        return cls(
            root=str(payload.get("root", "")),
            entries=tuple(entries),
            file_count=int(
                counts.get("files", sum(1 for e in entries if e.kind == "file"))
            ),
            dir_count=int(
                counts.get("dirs", sum(1 for e in entries if e.kind == "dir"))
            ),
            symlink_count=int(
                counts.get("symlinks", sum(1 for e in entries if e.kind == "symlink"))
            ),
            hashed_count=int(payload.get("hashed_count", 0)),
            total_bytes=int(payload.get("total_bytes", 0)),
            entries_truncated=bool(truncated.get("entries", False)),
            bytes_truncated=bool(truncated.get("bytes", False)),
            warnings=tuple(
                str(warning)
                for warning in (payload.get("warnings") or [])
                if isinstance(warning, str)
            ),
            evidence=Evidence(
                source=EVIDENCE_SNAPSHOT_SOURCE,
                method="walk-sha256",
                confidence=Confidence.HIGH,
                detail=f"coerced from JSON manifest ({len(entries)} entries)",
            ),
        )


@dataclass(frozen=True)
class ModifiedRecord:
    """One path present on both sides whose fingerprint changed."""

    path: str
    kind: str
    before_size: int
    after_size: int
    before_sha256: str | None
    after_sha256: str | None
    size_only: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "before_size": self.before_size,
            "after_size": self.after_size,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "size_only": self.size_only,
        }


@dataclass(frozen=True)
class FsDiff:
    """Bounded before/after classification of two filesystem snapshots."""

    verdict: str
    created: tuple[FsEntry, ...]
    deleted: tuple[FsEntry, ...]
    modified: tuple[ModifiedRecord, ...]
    created_total: int
    deleted_total: int
    modified_total: int
    unchanged_count: int
    created_truncated: bool
    deleted_truncated: bool
    modified_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "created": [entry.to_dict() for entry in self.created],
            "deleted": [entry.to_dict() for entry in self.deleted],
            "modified": [record.to_dict() for record in self.modified],
            "counts": {
                "created": self.created_total,
                "deleted": self.deleted_total,
                "modified": self.modified_total,
                "unchanged": self.unchanged_count,
            },
            "truncated": {
                "created": self.created_truncated,
                "deleted": self.deleted_truncated,
                "modified": self.modified_truncated,
            },
            "evidence": self.evidence.to_dict(),
        }


def _fingerprint(entry: FsEntry) -> tuple[str, str]:
    """Content identity of one entry: hash when available, size otherwise.

    Symlinks fingerprint by target text; unhashed (oversize or unreadable)
    files fall back to size -- an honest weaker identity, flagged in the diff.
    """
    if entry.kind == "symlink":
        return ("target", entry.target or "")
    if entry.kind == "file" and entry.hashed and entry.sha256 is not None:
        return ("sha256", entry.sha256)
    return ("size", str(entry.size))


def _sha256_file(path: Path) -> str:
    """Stream one file through sha256 in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(MAX_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_tree(
    root: Path,
    max_entries: int = MAX_ENTRIES,
    max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> FsSnapshot:
    """Walk ``root`` recursively into a bounded, deterministic manifest.

    Regular files get relative POSIX path, size and sha256 (files above
    ``max_hash_bytes`` are size-only, ``hashed: false``); directories and
    symlinks are recorded as entries too, and symlinks are never followed.
    Missing roots and non-directory roots are typed errors; entry overflow
    and byte-budget exhaustion are truncated flags plus warnings.
    """
    root = Path(root)
    if not root.exists():
        raise AnalysisError(f"file not found: {root}")
    if not root.is_dir():
        raise AnalysisError(f"not a directory: {root}")

    entries: list[FsEntry] = []
    warnings: list[str] = []
    file_count = dir_count = symlink_count = hashed_count = 0
    total_bytes = 0
    entries_truncated = False
    bytes_truncated = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if entries_truncated or bytes_truncated:
            break
        # Deterministic traversal: same tree -> same walk order -> same manifest.
        dirnames.sort()
        filenames.sort()
        base = Path(dirpath)
        for name in dirnames:
            candidate = base / name
            rel = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                # Never followed: os.walk already skips symlinked dirs here.
                symlink_count += 1
                target = os.readlink(candidate)[:MAX_SYMLINK_TARGET_CHARS]
                entries.append(FsEntry(kind="symlink", path=rel, size=0, target=target))
            else:
                dir_count += 1
                entries.append(FsEntry(kind="dir", path=rel, size=0))
        for name in filenames:
            if len(entries) >= max_entries:
                entries_truncated = True
                warnings.append(
                    f"entry cap {max_entries} reached; the rest of the tree is skipped"
                )
                break
            candidate = base / name
            rel = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                symlink_count += 1
                target = os.readlink(candidate)[:MAX_SYMLINK_TARGET_CHARS]
                entries.append(FsEntry(kind="symlink", path=rel, size=0, target=target))
                continue
            if not candidate.is_file():
                continue  # sockets/dev nodes and the like: not regular files
            size = candidate.stat().st_size
            if size > max_hash_bytes:
                # Size-only record: the content is never read into a hash.
                entries.append(FsEntry(kind="file", path=rel, size=size))
                file_count += 1
                continue
            if total_bytes + size > MAX_TOTAL_BYTES:
                bytes_truncated = True
                warnings.append(
                    f"byte budget {MAX_TOTAL_BYTES} exhausted after "
                    f"{total_bytes} bytes; the rest of the tree is skipped"
                )
                break
            try:
                digest = _sha256_file(candidate)
            except OSError as exc:
                warnings.append(f"cannot read {rel!r}: {exc}")
                entries.append(FsEntry(kind="file", path=rel, size=size))
                file_count += 1
                continue
            total_bytes += size
            hashed_count += 1
            file_count += 1
            entries.append(
                FsEntry(kind="file", path=rel, size=size, sha256=digest, hashed=True)
            )
        else:
            continue
        break  # inner break (cap or budget) also stops the walk

    if entries_truncated:
        # Counts describe what was actually recorded, never what was skipped.
        file_count = sum(1 for entry in entries if entry.kind == "file")
        dir_count = sum(1 for entry in entries if entry.kind == "dir")
        symlink_count = sum(1 for entry in entries if entry.kind == "symlink")
    entries.sort(key=lambda entry: entry.path)

    return FsSnapshot(
        root=str(root),
        entries=tuple(entries),
        file_count=file_count,
        dir_count=dir_count,
        symlink_count=symlink_count,
        hashed_count=hashed_count,
        total_bytes=total_bytes,
        entries_truncated=entries_truncated,
        bytes_truncated=bytes_truncated,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SNAPSHOT_SOURCE,
            method="walk-sha256",
            confidence=Confidence.HIGH,
            detail=(
                f"os.walk(followlinks=False): {file_count} files "
                f"({hashed_count} hashed, {total_bytes} bytes), {dir_count} dirs, "
                f"{symlink_count} symlinks"
            ),
        ),
    )


def _coerce_snapshot(snapshot: FsSnapshot | dict[str, Any], side: str) -> FsSnapshot:
    """Accept an FsSnapshot or a JSON manifest dict; nothing else."""
    if isinstance(snapshot, FsSnapshot):
        return snapshot
    if isinstance(snapshot, dict):
        return FsSnapshot.from_dict(snapshot)
    raise AnalysisError(
        f"malformed snapshot: {side} must be an FsSnapshot or its JSON dict"
    )


def diff_snapshots(
    before: FsSnapshot | dict[str, Any],
    after: FsSnapshot | dict[str, Any],
    max_lists: int = 512,
) -> FsDiff:
    """Classify two snapshots by relative path + content fingerprint.

    CREATED paths exist only in ``after``, DELETED only in ``before``;
    MODIFIED paths exist on both sides with a different fingerprint (hash
    when both sides are hashed, size fallback flagged ``size_only``).
    UNCHANGED is counted only. Every list is bounded to ``max_lists`` with
    per-list truncation flags; counts always report the true totals.
    """
    before_snap = _coerce_snapshot(before, "before")
    after_snap = _coerce_snapshot(after, "after")
    if max_lists <= 0:
        raise AnalysisError("max_lists must be a positive integer")

    before_index = {entry.path: entry for entry in before_snap.entries}
    after_index = {entry.path: entry for entry in after_snap.entries}

    created_paths = sorted(set(after_index) - set(before_index))
    deleted_paths = sorted(set(before_index) - set(after_index))
    common_paths = sorted(set(before_index) & set(after_index))

    created = [after_index[path] for path in created_paths]
    deleted = [before_index[path] for path in deleted_paths]
    modified: list[ModifiedRecord] = []
    unchanged = 0
    for path in common_paths:
        old = before_index[path]
        new = after_index[path]
        if _fingerprint(old) == _fingerprint(new):
            unchanged += 1
            continue
        hashed = (
            old.kind == "file"
            and new.kind == "file"
            and old.hashed
            and new.hashed
            and old.sha256 is not None
            and new.sha256 is not None
        )
        modified.append(
            ModifiedRecord(
                path=path,
                kind=new.kind,
                before_size=old.size,
                after_size=new.size,
                before_sha256=old.sha256,
                after_sha256=new.sha256,
                size_only=not hashed,
            )
        )

    created_kept = created[:max_lists]
    deleted_kept = deleted[:max_lists]
    modified_kept = modified[:max_lists]

    changed = bool(created) or bool(deleted) or bool(modified)
    return FsDiff(
        verdict="changed" if changed else "identical",
        created=tuple(created_kept),
        deleted=tuple(deleted_kept),
        modified=tuple(modified_kept),
        created_total=len(created),
        deleted_total=len(deleted),
        modified_total=len(modified),
        unchanged_count=unchanged,
        created_truncated=len(created) > len(created_kept),
        deleted_truncated=len(deleted) > len(deleted_kept),
        modified_truncated=len(modified) > len(modified_kept),
        evidence=Evidence(
            source=EVIDENCE_DIFF_SOURCE,
            method="hash-set-compare",
            confidence=Confidence.HIGH,
            detail=(
                f"{len(created)} created, {len(deleted)} deleted, "
                f"{len(modified)} modified, {unchanged} unchanged -> "
                f"{'changed' if changed else 'identical'}"
            ),
        ),
    )


def load_snapshot(path: str) -> FsSnapshot:
    """Load one ``fs_snapshot.json`` file back into an FsSnapshot."""
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise AnalysisError(f"file not found: {path}")
    if not candidate.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(path)!r}: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"snapshot is not valid JSON: {exc}") from exc
    return FsSnapshot.from_dict(payload)

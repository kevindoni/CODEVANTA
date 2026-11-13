"""Electron ASAR archive parser (read-only, never executes anything).

An ``.asar`` file is a concatenated container: an 8-byte *pickle* header that
carries two little-endian ``UInt32`` sizes, a JSON directory header, and then
the raw bytes of every file. The layout is::

    0x00  UInt32LE  size of the pickle that holds the header length (always 4)
    0x04  UInt32LE  byte length of the JSON header string
    0x08  JSON header (UTF-8), padded with zeroes to a 4-byte boundary
    base = 0x08 + pad4(json_len)   <- every file ``offset`` is relative to this

The JSON header is a tree: ``{"files": {"<name>": {...}, ...}}`` where a
directory node has its own ``files`` map and a file node carries ``size``, a
decimal-string ``offset`` relative to ``base``, optional ``integrity`` (SHA-256
of the whole file plus block hashes) and ``unpacked: true`` when Electron keeps
the bytes in a sibling ``app.asar.unpacked`` directory instead of the archive.

Guarantees:

* Pure parsing: :func:`parse_header` works on bytes with no filesystem access,
  so it is always available offline.
* Bounded work: the listing keeps at most :data:`MAX_FILES` file entries, the
  tree walk visits at most :data:`MAX_WALK_NODES` nodes at most
  :data:`MAX_DEPTH` levels deep, and the header itself is capped at
  :data:`MAX_HEADER_BYTES` (well under the house 256 MiB read ceiling).
* Extraction (:func:`extract_file`) reads a single range check-verified
  against the real file length and is capped at :data:`MAX_EXTRACT_BYTES`.
* Nothing here executes, writes, or follows links; malformed input raises
  :class:`~codevanta.core.report.AnalysisError` naming the defect.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_EXTRACT_BYTES",
    "EVIDENCE_METHOD",
    "EVIDENCE_METHOD_EXTRACT",
    "EVIDENCE_SOURCE",
    "MAX_DEPTH",
    "MAX_EXTRACT_BYTES",
    "MAX_FILES",
    "MAX_HEADER_BYTES",
    "MAX_WALK_NODES",
    "AsarEntry",
    "AsarExtract",
    "AsarHeader",
    "AsarListing",
    "extract_file",
    "list_archive",
    "parse_header",
]

#: Hard ceiling on listing file entries (bounded output; the walk keeps
#: counting beyond this so ``total_bytes`` stays honest, but no more rows
#: are kept).
MAX_FILES = 512

#: Hard ceiling on bytes one :func:`extract_file` call may return (8 MiB).
MAX_EXTRACT_BYTES = 8 * 1024 * 1024

#: Default ceiling for :func:`extract_file` callers that do not pin one.
DEFAULT_EXTRACT_BYTES = MAX_EXTRACT_BYTES

#: Hard ceiling on the JSON header read; real Electron headers are far below
#: this and the cap keeps a hostile file from exhausting memory.
MAX_HEADER_BYTES = 64 * 1024 * 1024

#: Hard ceiling on header-tree nodes visited by one listing (bounded work).
MAX_WALK_NODES = 65_536

#: Hard ceiling on header-tree depth (paths longer than this are pathological).
MAX_DEPTH = 64

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "asar.parse"

#: Evidence method for archive listings.
EVIDENCE_METHOD = "pickle_header_walk"

#: Evidence method for single-entry extraction.
EVIDENCE_METHOD_EXTRACT = "range_read"

_PICKLE_SIZE_FIELDS = struct.Struct("<II")


@dataclass(frozen=True)
class AsarHeader:
    """The decoded pickle header of an ASAR archive.

    Attributes:
        json_length: Byte length of the JSON header string (the second
            ``UInt32LE`` of the pickle header).
        base_offset: Absolute byte offset where file data begins; every file
            node's ``offset`` is relative to this.
        header: The parsed JSON tree (``{"files": {...}}``).
        evidence: Evidence record for the decode.
    """

    json_length: int
    base_offset: int
    header: dict[str, Any]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe summary (the tree itself stays out of reports)."""
        return {
            "json_length": self.json_length,
            "base_offset": self.base_offset,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AsarEntry:
    """One walked header-tree node (file or directory)."""

    path: str
    is_dir: bool
    size: int
    offset: int | None
    unpacked: bool
    integrity_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        data: dict[str, Any] = {
            "path": self.path,
            "type": "directory" if self.is_dir else "file",
            "size": self.size,
        }
        if self.offset is not None:
            data["offset"] = self.offset
        if self.unpacked:
            data["unpacked"] = True
        if self.integrity_hash is not None:
            data["integrity_sha256"] = self.integrity_hash
        return data


@dataclass(frozen=True)
class AsarListing:
    """Bounded inventory of one ASAR archive.

    Attributes:
        files: File entries, walk order, at most :data:`MAX_FILES`.
        file_count: Total file nodes found (may exceed ``len(files)``).
        dir_count: Total directory nodes found.
        total_bytes: Sum of file sizes (unpacked files included: their sizes
            are recorded in the header even though the bytes live outside).
        truncated: True when any bound (files kept, nodes visited, depth)
            cut the walk short.
        base_offset: Data base offset from the pickle header.
        top_level_apps: Top-level directories whose direct children include
            ``package.json`` -- heuristic evidence of a nested Electron app.
        evidence: Evidence record for the listing.
    """

    files: tuple[AsarEntry, ...]
    file_count: int
    dir_count: int
    total_bytes: int
    truncated: bool
    base_offset: int
    top_level_apps: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record."""
        return {
            "file_count": self.file_count,
            "dir_count": self.dir_count,
            "total_bytes": self.total_bytes,
            "truncated": self.truncated,
            "base_offset": self.base_offset,
            "top_level_apps": list(self.top_level_apps),
            "files": [entry.to_dict() for entry in self.files],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class AsarExtract:
    """One file extracted from an archive into memory."""

    path: str
    data: bytes
    sha256: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe record (the bytes themselves stay out)."""
        return {
            "path": self.path,
            "size": len(self.data),
            "sha256": self.sha256,
            "evidence": self.evidence.to_dict(),
        }


def parse_header(data: bytes) -> AsarHeader:
    """Decode the 8-byte pickle header plus JSON tree from ``data``.

    Pure function: no filesystem access, works on any bytes a caller already
    holds, so it is always available offline. Raises
    :class:`AnalysisError` for anything that is not a well-formed ASAR
    header: short pickle fields, an unexpected first pickle size, a
    non-UTF-8 or non-object header, or a tree without a ``files`` map.
    """
    if len(data) < 8:
        raise AnalysisError(
            f"not an asar archive: header needs 8 bytes, got {len(data)}"
        )
    pickle_size, json_length = _PICKLE_SIZE_FIELDS.unpack_from(data, 0)
    if pickle_size != 4:
        raise AnalysisError(
            f"not an asar archive: first pickle size is {pickle_size}, expected 4"
        )
    if json_length <= 0 or json_length > MAX_HEADER_BYTES:
        raise AnalysisError(
            f"asar header length {json_length} is outside 1..{MAX_HEADER_BYTES} bytes"
        )
    end = 8 + json_length
    if len(data) < end:
        raise AnalysisError(
            f"truncated asar header: need {end} bytes, file holds {len(data)}"
        )
    try:
        text = data[8:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"asar header is not valid UTF-8: {exc}") from exc
    try:
        tree = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"asar header is not valid JSON: {exc}") from exc
    if not isinstance(tree, dict) or not isinstance(tree.get("files"), dict):
        raise AnalysisError('asar header JSON must be an object with a "files" map')
    base_offset = 8 + _aligned4(json_length)
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD,
        confidence=Confidence.CERTAIN,
        extra={"json_length": json_length, "base_offset": base_offset},
    )
    return AsarHeader(
        json_length=json_length,
        base_offset=base_offset,
        header=tree,
        evidence=evidence,
    )


def _aligned4(value: int) -> int:
    """Round ``value`` up to a multiple of 4 (pickle payload alignment)."""
    return (value + 3) & ~3


def _decode_offset(node: dict[str, Any], path: str) -> int | None:
    """Decode a file node's ``offset`` (a decimal string in real archives)."""
    raw = node.get("offset")
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise AnalysisError(f"asar entry {path!r} has a non-integer offset {raw!r}")
    try:
        return int(raw)
    except ValueError as exc:
        raise AnalysisError(f"asar entry {path!r} has a bad offset {raw!r}") from exc


def _decode_size(node: dict[str, Any], path: str) -> int:
    """Decode a file node's ``size``, rejecting negatives and junk."""
    raw = node.get("size", 0)
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise AnalysisError(f"asar entry {path!r} has a non-integer size {raw!r}")
    try:
        size = int(raw)
    except ValueError as exc:
        raise AnalysisError(f"asar entry {path!r} has a bad size {raw!r}") from exc
    if size < 0:
        raise AnalysisError(f"asar entry {path!r} has a negative size {size}")
    return size


def _integrity_hash(node: dict[str, Any]) -> str | None:
    """Return the header's whole-file SHA-256 when an integrity block exists."""
    integrity = node.get("integrity")
    if isinstance(integrity, dict):
        digest = integrity.get("hash")
        if isinstance(digest, str) and digest:
            return digest
    return None


def _has_package_json_child(node: dict[str, Any]) -> bool:
    """True when a directory node's direct children include ``package.json``."""
    kids = node.get("files")
    return isinstance(kids, dict) and isinstance(kids.get("package.json"), dict)


def _walk(
    tree: dict[str, Any],
) -> tuple[tuple[AsarEntry, ...], int, int, int, bool, tuple[str, ...]]:
    """Walk the header tree, returning files, counts, bytes, bounds and apps.

    The walk is iterative (no recursion on hostile input), bounded by
    :data:`MAX_WALK_NODES` nodes and :data:`MAX_DEPTH` levels, and keeps the
    first :data:`MAX_FILES` file entries while still counting the rest so the
    totals stay honest about what was cut. ``top_level_apps`` collects
    depth-1 directories whose direct children include ``package.json``.
    """
    files: list[AsarEntry] = []
    file_count = 0
    dir_count = 0
    total_bytes = 0
    truncated = False
    top_level_apps: list[str] = []
    root_children = tree["files"]
    stack: list[tuple[str, dict[str, Any], int]] = [("", root_children, 0)]
    visited = 0
    while stack:
        prefix, children, depth = stack.pop()
        for name, node in children.items():
            if visited >= MAX_WALK_NODES:
                truncated = True
                break
            if not isinstance(name, str) or not isinstance(node, dict):
                truncated = True
                continue
            visited += 1
            path = f"{prefix}/{name}" if prefix else name
            kids = node.get("files")
            if isinstance(kids, dict):
                dir_count += 1
                if depth == 0 and _has_package_json_child(node):
                    top_level_apps.append(name)
                if depth + 1 >= MAX_DEPTH:
                    truncated = True
                    continue
                stack.append((path, kids, depth + 1))
                continue
            size = _decode_size(node, path)
            file_count += 1
            total_bytes += size
            if file_count > MAX_FILES:
                truncated = True  # accounting continues, rows stop
            if len(files) < MAX_FILES:
                unpacked = node.get("unpacked") is True
                files.append(
                    AsarEntry(
                        path=path,
                        is_dir=False,
                        size=size,
                        offset=_decode_offset(node, path),
                        unpacked=unpacked,
                        integrity_hash=_integrity_hash(node),
                    )
                )
        else:
            continue
        break
    return (
        tuple(files),
        file_count,
        dir_count,
        total_bytes,
        truncated,
        tuple(top_level_apps[:MAX_FILES]),
    )


def list_archive(path: Path) -> AsarListing:
    """List one ASAR archive's contents (bounded, read-only)."""
    try:
        stat = path.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {path}: {exc}") from exc
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    head = _read_head(path, stat.st_size)
    header = parse_header(head)
    (
        files,
        file_count,
        dir_count,
        total_bytes,
        truncated,
        top_level_apps,
    ) = _walk(header.header)
    return AsarListing(
        files=files,
        file_count=file_count,
        dir_count=dir_count,
        total_bytes=total_bytes,
        truncated=truncated,
        base_offset=header.base_offset,
        top_level_apps=top_level_apps,
        evidence=header.evidence,
    )


def _read_head(path: Path, file_size: int) -> bytes:
    """Read the pickle header plus JSON tree (never the whole archive)."""
    read_len = min(file_size, 8 + MAX_HEADER_BYTES)
    try:
        with path.open("rb") as handle:
            return handle.read(read_len)
    except OSError as exc:
        raise AnalysisError(f"cannot read {path}: {exc}") from exc


def _normalise_entry_path(entry_path: str) -> str:
    """Normalise an in-archive path and reject traversal components."""
    parts = [
        part
        for part in entry_path.replace("\\", "/").split("/")
        if part not in ("", ".")
    ]
    if not parts:
        raise AnalysisError("asar entry path must not be empty")
    if any(part == ".." for part in parts):
        raise AnalysisError(f"asar entry path must not traverse up: {entry_path!r}")
    return "/".join(parts)


def _find_node(tree: dict[str, Any], entry_path: str) -> dict[str, Any]:
    """Resolve a normalised in-archive path to its header node."""
    node: Any = tree
    for part in PurePosixPath(entry_path).parts:
        kids = node.get("files") if isinstance(node, dict) else None
        if not isinstance(kids, dict) or part not in kids:
            raise AnalysisError(f"asar entry not found: {entry_path!r}")
        node = kids[part]
    if not isinstance(node, dict):
        raise AnalysisError(f"asar entry not found: {entry_path!r}")
    return node


def extract_file(
    path: Path,
    entry_path: str,
    *,
    max_bytes: int = DEFAULT_EXTRACT_BYTES,
) -> AsarExtract:
    """Extract one in-archive file into memory (bounded, read-only).

    The header is parsed first, the entry resolved by exact path, and the
    range ``base_offset + offset .. + size`` is validated against the real
    file length before any byte is read. Files flagged ``unpacked`` are
    refused with a typed error: their bytes are not in this archive.
    """
    if max_bytes < 1 or max_bytes > MAX_EXTRACT_BYTES:
        raise AnalysisError(f"max_bytes must be between 1 and {MAX_EXTRACT_BYTES}")
    normalised = _normalise_entry_path(entry_path)
    try:
        stat = path.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {path}: {exc}") from exc
    if not path.is_file():
        raise AnalysisError(f"not a regular file: {path}")
    head = _read_head(path, stat.st_size)
    header = parse_header(head)
    node = _find_node(header.header, normalised)
    if isinstance(node.get("files"), dict):
        raise AnalysisError(f"asar entry is a directory: {normalised!r}")
    if node.get("unpacked") is True:
        raise AnalysisError(
            f"asar entry {normalised!r} is unpacked: its bytes live in the "
            "sibling app.asar.unpacked directory, not in this archive"
        )
    size = _decode_size(node, normalised)
    offset = _decode_offset(node, normalised)
    if offset is None:
        raise AnalysisError(f"asar entry {normalised!r} has no data offset")
    if size > max_bytes:
        raise AnalysisError(
            f"asar entry {normalised!r} is {size} bytes, above the "
            f"{max_bytes}-byte extract cap; refusing to read"
        )
    start = header.base_offset + offset
    end = start + size
    if start < 0 or end > stat.st_size:
        raise AnalysisError(
            f"asar entry {normalised!r} range [{start}, {end}) is outside the "
            f"archive ({stat.st_size} bytes): corrupt header"
        )
    try:
        with path.open("rb") as handle:
            handle.seek(start)
            data = handle.read(size)
    except OSError as exc:
        raise AnalysisError(f"cannot read {path}: {exc}") from exc
    if len(data) != size:
        raise AnalysisError(
            f"asar entry {normalised!r} truncated read: wanted {size}, "
            f"got {len(data)}"
        )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method=EVIDENCE_METHOD_EXTRACT,
        confidence=Confidence.CERTAIN,
        extra={"path": normalised, "range_start": start, "size": size},
    )
    return AsarExtract(
        path=normalised,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        evidence=evidence,
    )

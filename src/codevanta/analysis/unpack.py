"""Recursive bounded archive manifests, in memory only (stdlib parsing).

One entry point -- :func:`build_unpack_manifest` -- turns raw archive bytes
into a JSON-safe tree of :class:`UnpackNode` records. Detection is magic-gated
in the style of the container inspectors: zip (``PK\\x03\\x04``), tar
(``ustar``), gzip, bzip2, xz and cpio newc (``070701``/``070702``). Compressed
tar archives are handled by bound-decompressing the stream layer first and
parsing the inner tar; single-stream gzip/bzip2/xz payloads become a ``stream``
node whose child is the expanded bytes (which themselves may be a nested
archive, so zip-in-gzip and tar-in-xz unpack recursively).

Guards
------
Work is bounded, and every bound is a truncation flag plus warning -- honest
over hard errors, except where the input cannot be parsed at all:

* :data:`MAX_DEPTH` levels of nested-archive descent (the outer archive is
  depth 0); deeper archives are listed but not unpacked.
* :data:`MAX_ENTRIES` entries listed per archive; the rest are skipped.
* :data:`MAX_TOTAL_BYTES` total accounted bytes across every nesting level
  (declared sizes spend the same budget as materialized content, so a lying
  header cannot hide behind a small compressed shell).
* Zip-bomb guard: an entry whose declared size exceeds its compressed size by
  more than :data:`MAX_RATIO` to one is reported as a bomb suspect and its
  content is never read; stream expansion is additionally capped at the
  remaining budget during decompression, so an oversized gzip is truncated
  rather than slurped.
* Leaves at most :data:`MAX_LEAF_BYTES` are read back (for ``sha256`` and
  nested-archive descent); bigger leaves are listed from header metadata only.

A magic-matched but corrupt container is a typed
:class:`~codevanta.core.report.AnalysisError`; unrecognized bytes raise the
same error at the root but are tolerated (kept as plain files) when found
nested inside an archive. Nothing is extracted to disk, fetched, or executed.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_DEPTH",
    "MAX_ENTRIES",
    "MAX_LEAF_BYTES",
    "MAX_RATIO",
    "MAX_TOTAL_BYTES",
    "UnpackManifest",
    "UnpackNode",
    "build_unpack_manifest",
    "detect_format",
]

#: Deepest nested-archive descent (outer archive is depth 0, its children 1).
MAX_DEPTH = 4

#: Entries listed per archive before the rest are skipped (truncated flag).
MAX_ENTRIES = 512

#: Ceiling on bytes accounted across every nesting level (declared + read).
MAX_TOTAL_BYTES = 64 * 1024 * 1024

#: Largest leaf read back (for sha256 and nested-archive descent); bigger
#: leaves are listed from header metadata only.
MAX_LEAF_BYTES = 1024 * 1024

#: Declared-size / compressed-size ratio above which an entry is reported as
#: a compression-bomb suspect and its content is never read.
MAX_RATIO = 1000

#: Shared evidence ``source`` for this lane.
EVIDENCE_SOURCE = "web.unpack"

_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_EMPTY_MAGIC = b"PK\x05\x06"
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_CPIO_MAGICS = (b"070701", b"070702")
_CPIO_TRAILER = "TRAILER!!!"
_TAR_USTAR_MAGIC = b"ustar"
_CPIO_HEADER_BYTES = 110
_STREAM_SUFFIX = {"gzip": "gunzip", "bz2": "bunzip2", "xz": "unxz"}
_READ_CHUNK = 65536


@dataclass(frozen=True)
class UnpackNode:
    """One entry of the manifest tree (JSON-safe via :meth:`to_dict`).

    ``kind`` is ``archive`` for parsed containers, ``stream`` for
    compressed-stream nodes, ``file`` for leaves, ``dir`` for directories and
    ``link`` for tar non-regular/non-directory members. ``size`` is the
    declared (or measured) byte size; ``truncated`` marks nodes whose listing
    or content had to be bounded.
    """

    path: str
    kind: str
    size: int
    compressed_size: int | None = None
    format: str | None = None
    sha256: str | None = None
    truncated: bool = False
    children: tuple[UnpackNode, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "truncated": self.truncated,
        }
        if self.compressed_size is not None:
            payload["compressed_size"] = self.compressed_size
        if self.format is not None:
            payload["format"] = self.format
        if self.sha256 is not None:
            payload["sha256"] = self.sha256
        if self.children is not None:
            payload["children"] = [child.to_dict() for child in self.children]
        return payload


@dataclass(frozen=True)
class UnpackManifest:
    """Bounded recursive manifest of one archive blob."""

    root_format: str
    root: UnpackNode
    entry_count: int
    total_bytes: int
    depth_reached: int
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_format": self.root_format,
            "entry_count": self.entry_count,
            "total_bytes": self.total_bytes,
            "depth_reached": self.depth_reached,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "root": self.root.to_dict(),
            "evidence": self.evidence.to_dict(),
        }


def detect_format(data: bytes) -> str | None:
    """Return the archive format ``data`` starts with, or ``None`` on a miss."""
    if data[:4] in (_ZIP_MAGIC, _ZIP_EMPTY_MAGIC):
        return "zip"
    if data[:2] == _GZIP_MAGIC:
        return "gzip"
    if data[:3] == _BZ2_MAGIC:
        return "bz2"
    if data[:6] == _XZ_MAGIC:
        return "xz"
    if data[:6] in _CPIO_MAGICS:
        return "cpio-newc"
    if len(data) >= 512 and data[257:262] == _TAR_USTAR_MAGIC:
        return "tar"
    return None


class _Budget:
    """Running byte budget shared by every nesting level.

    Declared sizes spend the same budget as materialized content: a small zip
    whose entries claim gigabytes exhausts the budget exactly like an actually
    extracted bomb would.
    """

    __slots__ = ("exhausted", "remaining")

    def __init__(self) -> None:
        self.remaining = MAX_TOTAL_BYTES
        self.exhausted = False

    def spend(self, amount: int) -> bool:
        """Account ``amount`` bytes; ``False`` means it did not fully fit."""
        if amount <= 0:
            return True
        fitted = min(amount, self.remaining)
        self.remaining -= fitted
        if fitted < amount or self.remaining == 0:
            self.exhausted = True
        return fitted == amount

    def fits(self, amount: int) -> bool:
        return amount <= self.remaining


class _Walk:
    """Mutable state threaded through the recursion (results stay frozen)."""

    __slots__ = ("budget", "depth_reached", "entry_count", "hashes", "warnings")

    def __init__(self, hashes: bool) -> None:
        self.hashes = hashes
        self.budget = _Budget()
        self.warnings: list[str] = []
        self.entry_count = 0
        self.depth_reached = 0

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


def _join(parent: str, name: str) -> str:
    """Normalize an archive member name under ``parent`` (safe, relative)."""
    clean = name.replace("\\", "/")
    while clean.startswith("/"):
        clean = clean[1:]
    while clean.endswith("/"):
        clean = clean[:-1]
    if not clean:
        return parent
    return f"{parent}/{clean}"


def _tree_truncated(node: UnpackNode) -> bool:
    """True when any node in the subtree had to be bounded."""
    if node.truncated:
        return True
    return any(_tree_truncated(child) for child in node.children or ())


def _leaf(
    path: str,
    size: int,
    *,
    compressed_size: int | None = None,
    content: bytes | None = None,
    hashes: bool = True,
    truncated: bool = False,
) -> UnpackNode:
    """Build a ``file`` node, hashing ``content`` when it was read back."""
    sha = (
        hashlib.sha256(content).hexdigest() if content is not None and hashes else None
    )
    return UnpackNode(
        path=path,
        kind="file",
        size=size,
        compressed_size=compressed_size,
        sha256=sha,
        truncated=truncated,
    )


def _decompress_bounded(data: bytes, fmt: str, allowance: int) -> tuple[bytes, bool]:
    """Decompress ``data`` capped at ``allowance`` bytes; return (payload, over).

    The cap is enforced during decompression, so an oversized gzip/bz2/xz
    stream is truncated at the budget instead of being slurped whole.
    """
    if fmt == "bz2":
        engine: Any = bz2.BZ2Decompressor()
    elif fmt == "xz":
        engine = lzma.LZMADecompressor()
    else:
        engine = zlib.decompressobj(zlib.MAX_WBITS | 16)
    cap = allowance + 1  # one extra byte detects overflow exactly
    out = bytearray()
    overflow = False
    pos = 0
    while pos < len(data) and not engine.eof:
        chunk = data[pos : pos + _READ_CHUNK]
        pos += len(chunk)
        try:
            out += engine.decompress(chunk)
        except (OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
            raise AnalysisError(f"corrupt {fmt} stream: {exc}") from exc
        if len(out) > cap:
            del out[cap:]
            overflow = True
            break
    return bytes(out), overflow


def _walk(state: _Walk, data: bytes, path: str, depth: int, fmt: str) -> UnpackNode:
    """Dispatch one blob to its format walker (recursion point for nesting)."""
    state.depth_reached = max(state.depth_reached, depth)
    if depth > MAX_DEPTH:
        state.warn(f"descent bounded at depth {MAX_DEPTH}; '{path}' not unpacked")
        return UnpackNode(
            path=path, kind="archive", size=len(data), format=fmt, truncated=True
        )
    if fmt == "zip":
        return _walk_zip(state, data, path, depth)
    if fmt == "tar":
        return _walk_tar(state, data, path, depth)
    if fmt == "cpio-newc":
        return _walk_cpio(state, data, path)
    return _walk_stream(state, data, path, depth, fmt)


def _walk_zip(state: _Walk, data: bytes, path: str, depth: int) -> UnpackNode:
    """List a zip archive recursively, bounded by entries and byte budget."""
    children: list[UnpackNode] = []
    truncated = False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                truncated = True
                state.warn(f"'{path}': entries bounded at {MAX_ENTRIES}, rest skipped")
            for info in infos[:MAX_ENTRIES]:
                if state.budget.exhausted:
                    truncated = True
                    state.warn(f"'{path}': byte budget exhausted; rest skipped")
                    break
                member_path = _join(path, info.filename)
                if info.is_dir():
                    state.entry_count += 1
                    children.append(UnpackNode(path=member_path, kind="dir", size=0))
                    continue
                state.entry_count += 1
                children.append(_zip_entry(state, archive, info, member_path, depth))
    except (zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as exc:
        raise AnalysisError(f"'{path}': not a readable zip archive: {exc}") from exc
    return UnpackNode(
        path=path,
        kind="archive",
        size=len(data),
        format="zip",
        truncated=truncated,
        children=tuple(children),
    )


def _zip_entry(
    state: _Walk,
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    member_path: str,
    depth: int,
) -> UnpackNode:
    """List one zip member; read small content for hashing/descent only."""
    size = info.file_size
    compressed = info.compress_size
    bomb_suspect = compressed > 0 and size > compressed * MAX_RATIO
    declared_fit = state.budget.spend(size)
    if bomb_suspect:
        state.warn(
            f"'{member_path}': declared size {size} vs compressed {compressed} "
            f"exceeds {MAX_RATIO}:1; bomb suspect, content not read"
        )
    if not declared_fit:
        state.warn(f"'{member_path}': byte budget exhausted; content not read")
        return _leaf(
            member_path, size, compressed_size=compressed, hashes=state.hashes,
            truncated=True,
        )
    content: bytes | None = None
    if not bomb_suspect and size <= MAX_LEAF_BYTES and state.budget.fits(size):
        try:
            with archive.open(info) as handle:
                content = handle.read(MAX_LEAF_BYTES + 1)
        except (zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as exc:
            state.warn(f"'{member_path}': content unread: {exc}")
            content = None
        if content is not None and len(content) > MAX_LEAF_BYTES:
            state.warn(f"'{member_path}': content exceeds the leaf cap; not read")
            content = None
        elif content is not None and len(content) != size:
            state.warn(
                f"'{member_path}': declared {size} bytes but read {len(content)}; "
                "listed from metadata"
            )
            content = None
    if content is not None:
        inner = detect_format(content)
        if inner is not None:
            return _walk(state, content, member_path, depth + 1, inner)
        return _leaf(
            member_path,
            size,
            compressed_size=compressed,
            content=content,
            hashes=state.hashes,
        )
    return _leaf(
        member_path,
        size,
        compressed_size=compressed,
        hashes=state.hashes,
        truncated=bomb_suspect,
    )


def _walk_tar(state: _Walk, data: bytes, path: str, depth: int) -> UnpackNode:
    """List a tar archive (plain bytes) recursively, bounded and budgeted."""
    children: list[UnpackNode] = []
    truncated = False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            counted = 0
            member = archive.next()
            while member is not None:
                if counted >= MAX_ENTRIES:
                    truncated = True
                    state.warn(
                        f"'{path}': entries bounded at {MAX_ENTRIES}, rest skipped"
                    )
                    break
                if state.budget.exhausted:
                    truncated = True
                    state.warn(f"'{path}': byte budget exhausted; rest skipped")
                    break
                member_path = _join(path, member.name)
                state.entry_count += 1
                if member.isfile():
                    children.append(
                        _tar_entry(state, archive, member, member_path, depth)
                    )
                elif member.isdir():
                    children.append(UnpackNode(path=member_path, kind="dir", size=0))
                else:
                    children.append(
                        UnpackNode(path=member_path, kind="link", size=member.size)
                    )
                counted += 1
                member = archive.next()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise AnalysisError(f"'{path}': not a readable tar archive: {exc}") from exc
    return UnpackNode(
        path=path,
        kind="archive",
        size=len(data),
        format="tar",
        truncated=truncated,
        children=tuple(children),
    )


def _tar_entry(
    state: _Walk,
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    member_path: str,
    depth: int,
) -> UnpackNode:
    """List one tar member; read small content for hashing/descent only."""
    size = member.size
    declared_fit = state.budget.spend(size)
    if not declared_fit:
        state.warn(f"'{member_path}': byte budget exhausted; content not read")
        return _leaf(member_path, size, hashes=state.hashes, truncated=True)
    content: bytes | None = None
    if size <= MAX_LEAF_BYTES and state.budget.fits(size):
        handle = archive.extractfile(member)
        if handle is not None:
            content = handle.read(MAX_LEAF_BYTES + 1)
        if content is not None and len(content) != size:
            state.warn(
                f"'{member_path}': declared {size} bytes but read {len(content)}; "
                "listed from metadata"
            )
            content = None
    if content is not None:
        inner = detect_format(content)
        if inner is not None:
            return _walk(state, content, member_path, depth + 1, inner)
        return _leaf(member_path, size, content=content, hashes=state.hashes)
    return _leaf(member_path, size, hashes=state.hashes)


def _walk_stream(
    state: _Walk, data: bytes, path: str, depth: int, fmt: str
) -> UnpackNode:
    """Bound-decompress a single gzip/bz2/xz stream; expansion may nest further."""
    allowance = state.budget.remaining
    payload, overflow = _decompress_bounded(data, fmt, allowance)
    size = len(payload)
    declared_fit = state.budget.spend(size)
    truncated = overflow or not declared_fit
    if overflow:
        state.warn(
            f"'{path}': expanded stream exceeds the remaining "
            f"{allowance}-byte budget; truncated"
        )
    ratio = size / max(len(data), 1)
    if ratio > MAX_RATIO:
        state.warn(
            f"'{path}': expansion ratio {ratio:.0f}:1 exceeds {MAX_RATIO}:1; "
            "possible decompression bomb"
        )
    stream_path = f"{path}!{_STREAM_SUFFIX[fmt]}"
    if size == 0:
        return UnpackNode(
            path=path, kind="stream", size=len(data), format=fmt, truncated=truncated
        )
    inner = detect_format(payload)
    if inner is not None and not truncated:
        child = _walk(state, payload, stream_path, depth + 1, inner)
        return UnpackNode(
            path=path,
            kind="stream",
            size=len(data),
            format=fmt,
            truncated=truncated,
            children=(child,),
        )
    sha = (
        hashlib.sha256(payload).hexdigest()
        if state.hashes and size <= MAX_LEAF_BYTES
        else None
    )
    child = UnpackNode(
        path=stream_path,
        kind="file",
        size=size,
        sha256=sha,
        truncated=truncated,
    )
    return UnpackNode(
        path=path,
        kind="stream",
        size=len(data),
        format=fmt,
        truncated=truncated,
        children=(child,),
    )


def _walk_cpio(state: _Walk, data: bytes, path: str) -> UnpackNode:
    """Walk cpio newc headers only (names, modes, sizes); no content reads."""
    children: list[UnpackNode] = []
    truncated = False
    pos = 0
    counted = 0
    while pos + _CPIO_HEADER_BYTES <= len(data):
        header = data[pos : pos + _CPIO_HEADER_BYTES]
        if header[:6] not in _CPIO_MAGICS:
            if counted == 0:
                raise AnalysisError(
                    f"'{path}': not a newc cpio archive (bad header magic)"
                )
            state.warn(f"'{path}': cpio walk stopped at a malformed header")
            truncated = True
            break
        try:
            fields = [int(header[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        except ValueError as exc:
            raise AnalysisError(
                f"'{path}': malformed cpio header at offset {pos}: {exc}"
            ) from exc
        mode = fields[1]
        filesize = fields[6]
        namesize = fields[11]
        name_bytes = data[
            pos + _CPIO_HEADER_BYTES : pos + _CPIO_HEADER_BYTES + namesize
        ]
        if len(name_bytes) < namesize:
            state.warn(f"'{path}': cpio truncated inside an entry name; walk stopped")
            truncated = True
            break
        name = name_bytes[:-1].decode("utf-8", errors="replace") if namesize else ""
        if name == _CPIO_TRAILER:
            break
        if counted >= MAX_ENTRIES:
            truncated = True
            state.warn(f"'{path}': entries bounded at {MAX_ENTRIES}, rest skipped")
            break
        state.entry_count += 1
        counted += 1
        kind = "dir" if (mode & 0o170000) == 0o040000 else "file"
        entry_size = filesize if kind == "file" else 0
        declared_fit = state.budget.spend(entry_size)
        node = UnpackNode(
            path=_join(path, name), kind=kind, size=entry_size, truncated=not declared_fit
        )
        children.append(node)
        if not declared_fit:
            state.warn(f"'{path}': byte budget exhausted; rest skipped")
            truncated = True
            break
        pos = (pos + _CPIO_HEADER_BYTES + namesize + filesize + 3) & ~3
    if counted == 0 and len(data) < _CPIO_HEADER_BYTES:
        truncated = True
        state.warn(f"'{path}': cpio archive shorter than one header")
    return UnpackNode(
        path=path,
        kind="archive",
        size=len(data),
        format="cpio-newc",
        truncated=truncated,
        children=tuple(children),
    )


def build_unpack_manifest(data: bytes, *, hashes: bool = True) -> UnpackManifest:
    """Build a bounded recursive manifest for archive ``data`` (memory only).

    No entry is ever written to disk: nested archives are unpacked in memory,
    bounded by :data:`MAX_DEPTH`, :data:`MAX_ENTRIES`, :data:`MAX_TOTAL_BYTES`
    and the ratio guard documented in the module docstring.
    """
    fmt = detect_format(data)
    if fmt is None:
        raise AnalysisError(
            "input does not match a known archive format "
            "(zip, tar, gzip, bzip2, xz, cpio-newc)"
        )
    state = _Walk(hashes=hashes)
    root = _walk(state, data, "archive", 0, fmt)
    total = MAX_TOTAL_BYTES - state.budget.remaining
    return UnpackManifest(
        root_format=fmt,
        root=root,
        entry_count=state.entry_count,
        total_bytes=total,
        depth_reached=state.depth_reached,
        truncated=_tree_truncated(root) or state.budget.exhausted,
        warnings=tuple(state.warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="stdlib_zipfile_tarfile_headers",
            confidence=Confidence.HIGH,
            detail=(
                f"{state.entry_count} entries to depth {state.depth_reached}; "
                f"{total} of {MAX_TOTAL_BYTES} budgeted bytes accounted"
            ),
        ),
    )

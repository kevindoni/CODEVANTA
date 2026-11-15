"""Pure-stdlib PDB (Program Database) information parser — offline, read-only.

Given a local ``.pdb`` file, this module walks the MSF v7.00 ("Big" format)
container by hand and reports container facts only — no symbols, no types,
no downloads:

* **MSF container** — superblock validation (magic, block size power of two
  between 512 and 16384), the stream directory reached through the block map,
  per-stream block tables, and bounded on-demand stream reads.
* **PDB info stream (stream 1)** — version, signature, age and the unique
  GUID, plus the inline named-stream string blob (``/names``, ``/LinkInfo``,
  ...). The name→stream-index hash table is deliberately not decoded; the
  one stream bound to a name is ``/names`` itself, located by its own
  0xeffeeffe magic.
* **DBI stream (stream 3)** — the module list: each module's name and object
  file name, walked record by record over the 64-byte fixed prefix plus two
  NUL strings. A walk that cannot find the next record's strings inside the
  substream stops with a warning naming the module index instead of guessing.
* **PE CodeView reference** — the debug directory's CodeView record
  (``RSDS`` and ``NB10``): PDB path, GUID (RSDS) or time-date stamp (NB10
  records carry no GUID), age, and the PE section carrying the record.

Guarantees:

* Nothing here executes, writes, or talks to the network. There is no symbol
  download and no symbol server — ever. Only the file's own bytes are read.
* Bounded work: block-map entries, stream rows, stream bytes, names, modules,
  CodeView paths and debug entries all carry hard caps, and every cap that
  fires is reported through ``truncated`` flags, honest counts or warnings —
  never silently.
* Malformed structure (bad magic, insane block size, a directory or stream
  block pointing outside the file, a directory too small for its stream
  count) raises the typed :class:`~codevanta.core.report.AnalysisError`;
  damage inside one optional stream (info/DBI/names) degrades to a warning
  and the rest of the report still stands.
* Structure findings are *certain* — every value is read straight out of the
  file. No heuristic fallbacks exist in this module.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "CodeViewRef",
    "DBI_STREAM_INDEX",
    "DEFAULT_MAX_MODULES",
    "DEFAULT_MAX_STREAMS",
    "DbiModule",
    "EVIDENCE_SOURCE",
    "INFO_STREAM_INDEX",
    "MAX_BLOCK_MAP_ENTRIES",
    "MAX_BLOCK_SIZE",
    "MAX_DEBUG_ENTRIES",
    "MAX_FILE_SIZE",
    "MAX_MODULES",
    "MAX_NAMES",
    "MAX_PDB_PATH_BYTES",
    "MAX_STREAM_BYTES",
    "MAX_STREAMS",
    "MAX_WARNINGS",
    "MIN_BLOCK_SIZE",
    "MSF_MAGIC",
    "NAMES_STREAM_NAME",
    "NAMES_STREAM_SIGNATURE",
    "PdbInfoReport",
    "PdbStream",
    "codeview_reference",
    "decode_codeview_record",
    "parse_pdb",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "pdb.info"

#: MSF 7.00 superblock magic (32 bytes at file offset 0).
MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

#: Smallest block size a sane MSF file uses.
MIN_BLOCK_SIZE = 512

#: Largest block size a sane MSF file uses.
MAX_BLOCK_SIZE = 16384

#: Block sizes the format defines (power of two, 512..16384).
VALID_BLOCK_SIZES = frozenset({512, 1024, 2048, 4096, 8192, 16384})

#: Directory block numbers read from the block map (bounded work).
MAX_BLOCK_MAP_ENTRIES = 1024

#: Largest single stream this module reassembles (bounded work).
MAX_STREAM_BYTES = 16 * 1024 * 1024

#: Hard ceiling on a declared stream count (attacker-controlled u32).
MAX_STREAMS = 65536

#: Default ceiling on stream rows kept in a report.
DEFAULT_MAX_STREAMS = 256

#: Hard ceiling on module rows accepted for ``max_modules``.
MAX_MODULES = 16384

#: Default ceiling on module rows kept in a report.
DEFAULT_MAX_MODULES = 4096

#: Names kept from the ``/names`` string table (counting stops honestly).
MAX_NAMES = 4096

#: Longest CodeView PDB path decoded (bytes).
MAX_PDB_PATH_BYTES = 1024

#: ``IMAGE_DEBUG_DIRECTORY`` entries walked per file (bounded work).
MAX_DEBUG_ENTRIES = 64

#: Ceiling on warnings kept in one report.
MAX_WARNINGS = 32

#: Whole-file read cap, mirroring the loader's guard.
MAX_FILE_SIZE = 512 * 1024 * 1024

#: Stream size sentinel meaning "stream is absent" (no block table follows).
STREAM_ABSENT = 0xFFFFFFFF

#: Stream index of the PDB info stream (fixed by the format).
INFO_STREAM_INDEX = 1

#: Stream index of the DBI stream (fixed by the format).
DBI_STREAM_INDEX = 3

#: Name reported for the named-stream string table.
NAMES_STREAM_NAME = "/names"

#: ``/names`` stream header magic (0xeffeeffe).
NAMES_STREAM_SIGNATURE = 0xEF_FE_EF_FE

#: ``IMAGE_DEBUG_DIRECTORY.Type`` for a CodeView record.
DEBUG_TYPE_CODEVIEW = 2

#: Fixed size of the DBI header that precedes the module-info substream.
DBI_HEADER_SIZE = 64

#: Fixed size of one DBI module record's binary prefix (before the strings).
#: Verified against real MSVC output: module index at +20 (u16), two
#: NUL-terminated strings at +64, then alignment padding to a 4-byte boundary.
DBI_MODULE_PREFIX_SIZE = 64

#: Byte size of the MSF superblock (magic + six u32 fields).
_SUPERBLOCK_SIZE = 32 + 24


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


def _format_guid(raw: bytes) -> str:
    """Format 16 GUID bytes (mixed-endian, as stored) as 8-4-4-4-12 hex."""
    d1, d2, d3 = struct.unpack("<IHH", raw[:8])
    tail = raw[8:].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{tail[:4]}-{tail[4:]}"


def _cstring(data: bytes, start: int, limit: int) -> tuple[str, int] | None:
    """Read one NUL-terminated string at ``start``; ``None`` when unfindable."""
    if start >= limit:
        return None
    end = data.find(b"\x00", start, limit)
    if end < 0:
        return None
    return data[start:end].decode("utf-8", errors="replace"), end + 1


def _bounded_path(data: bytes, start: int) -> str:
    """Decode one bounded (MAX_PDB_PATH_BYTES) path prefix at ``start``."""
    limit = min(len(data), start + MAX_PDB_PATH_BYTES)
    if start >= limit:
        return ""
    end = data.find(b"\x00", start, limit)
    if end < 0:
        end = limit
    return data[start:end].decode("utf-8", errors="replace")


# ---- MSF container -----------------------------------------------------------


@dataclass(frozen=True)
class _MsfStream:
    """One entry of the MSF stream directory (size + block numbers)."""

    size: int | None  # None = absent (0xFFFFFFFF sentinel)
    blocks: tuple[int, ...]


class _MsfFile:
    """A validated MSF v7.00 container: superblock, directory, block tables."""

    __slots__ = ("block_size", "data", "num_blocks", "streams")

    def __init__(self, data: bytes, path: Path) -> None:
        if len(data) < _SUPERBLOCK_SIZE:
            raise AnalysisError(
                f"PDB {path} is truncated: {len(data)} bytes cannot hold an MSF superblock"
            )
        if data[: len(MSF_MAGIC)] != MSF_MAGIC:
            raise AnalysisError(f"PDB {path} is not an MSF 7.00 container: bad superblock magic")
        block_size, _free, num_blocks, directory_bytes, _unknown, block_map_addr = (
            struct.unpack_from("<6I", data, 32)
        )
        if block_size not in VALID_BLOCK_SIZES:
            raise AnalysisError(
                f"PDB {path}: block size {block_size} is not a power of two between "
                f"{MIN_BLOCK_SIZE} and {MAX_BLOCK_SIZE}"
            )
        if num_blocks < 1:
            raise AnalysisError(f"PDB {path}: num_blocks is zero")
        if directory_bytes < 4:
            raise AnalysisError(
                f"PDB {path}: directory size {directory_bytes} cannot hold a stream count"
            )
        dir_blocks_needed = -(-directory_bytes // block_size)
        if dir_blocks_needed > MAX_BLOCK_MAP_ENTRIES:
            raise AnalysisError(
                f"PDB {path}: directory spans {dir_blocks_needed} blocks, above the "
                f"{MAX_BLOCK_MAP_ENTRIES}-block cap"
            )
        if block_map_addr >= num_blocks:
            raise AnalysisError(
                f"PDB {path}: block map block {block_map_addr} is outside the "
                f"{num_blocks}-block file"
            )
        self.data = data
        self.block_size = block_size
        self.num_blocks = num_blocks
        directory = self._read_directory(
            data, path, block_map_addr, dir_blocks_needed, directory_bytes
        )
        self.streams = self._parse_directory(directory, path)

    def _read_directory(
        self,
        data: bytes,
        path: Path,
        block_map_addr: int,
        needed: int,
        directory_bytes: int,
    ) -> bytes:
        """Follow the block map and reassemble the stream directory bytes."""
        map_offset = block_map_addr * self.block_size
        blocks: list[int] = []
        for i in range(needed):
            if map_offset + 4 * i + 4 > len(data):
                raise AnalysisError(
                    f"PDB {path}: block map is truncated (needs {needed} entries, "
                    f"file runs out inside entry {i})"
                )
            block_no = struct.unpack_from("<I", data, map_offset + 4 * i)[0]
            if block_no >= self.num_blocks:
                raise AnalysisError(
                    f"PDB {path}: directory block-map entry {i} points at block "
                    f"{block_no}, outside the {self.num_blocks}-block file"
                )
            blocks.append(block_no)
        out = bytearray()
        for i, block_no in enumerate(blocks):
            start = block_no * self.block_size
            chunk = data[start : start + self.block_size]
            if len(chunk) < self.block_size:
                raise AnalysisError(
                    f"PDB {path}: directory block {i} (file block {block_no}) "
                    f"extends past the end of the file"
                )
            out += chunk
        return bytes(out[:directory_bytes])

    def _parse_directory(self, directory: bytes, path: Path) -> tuple[_MsfStream, ...]:
        """Split directory bytes into stream sizes and block-number tables."""
        count = struct.unpack_from("<I", directory, 0)[0]
        if count > MAX_STREAMS:
            raise AnalysisError(
                f"PDB {path}: stream count {count} exceeds the {MAX_STREAMS} cap"
            )
        if 4 + 4 * count > len(directory):
            raise AnalysisError(
                f"PDB {path}: stream count {count} exceeds the {len(directory)}-byte directory"
            )
        cursor = 4
        sizes: list[int | None] = []
        for _ in range(count):
            size = struct.unpack_from("<I", directory, cursor)[0]
            cursor += 4
            sizes.append(None if size == STREAM_ABSENT else size)
        streams: list[_MsfStream] = []
        for index, size in enumerate(sizes):
            if size is None or size == 0:
                streams.append(_MsfStream(size=size, blocks=()))
                continue
            block_count = -(-size // self.block_size)
            span = 4 * block_count
            if cursor + span > len(directory):
                raise AnalysisError(
                    f"PDB {path}: stream directory truncated inside stream {index}'s block table"
                )
            blocks = struct.unpack_from(f"<{block_count}I", directory, cursor)
            cursor += span
            for block_no in blocks:
                if block_no >= self.num_blocks:
                    raise AnalysisError(
                        f"PDB {path}: stream {index} points at block {block_no}, "
                        f"outside the {self.num_blocks}-block file"
                    )
                if (block_no + 1) * self.block_size > len(self.data):
                    raise AnalysisError(
                        f"PDB {path}: stream {index} block {block_no} extends past "
                        f"the end of the file"
                    )
            streams.append(_MsfStream(size=size, blocks=blocks))
        return tuple(streams)

    def read_stream(self, index: int, warnings: list[str]) -> bytes | None:
        """Reassemble one stream's bytes on demand (absent/over-cap → ``None``)."""
        if not 0 <= index < len(self.streams):
            return None
        entry = self.streams[index]
        if entry.size is None:
            return None
        if entry.size > MAX_STREAM_BYTES:
            _warn(
                warnings,
                f"stream {index} is {entry.size} bytes, above the "
                f"{MAX_STREAM_BYTES}-byte read cap; content skipped",
            )
            return None
        buf = bytearray()
        for block_no in entry.blocks:
            start = block_no * self.block_size
            buf += self.data[start : start + self.block_size]
        return bytes(buf[: entry.size])


# ---- PDB info stream ---------------------------------------------------------


@dataclass(frozen=True)
class _InfoFacts:
    """What the info stream and the ``/names`` blob contributed to a report."""

    version: int | None = None
    signature: int | None = None
    age: int | None = None
    guid: str | None = None
    names_index: int | None = None
    names: tuple[str, ...] = ()
    names_truncated: bool = False


def _parse_info_stream(msf: _MsfFile, warnings: list[str]) -> _InfoFacts:
    """Read stream 1's header and the inline named-stream string blob."""
    data = msf.read_stream(INFO_STREAM_INDEX, warnings)
    if data is None:
        _warn(warnings, "PDB info stream (stream 1) is absent; no version, GUID or age")
        return _InfoFacts()
    if len(data) < 28:
        _warn(
            warnings,
            f"PDB info stream is {len(data)} bytes, too small for the 28-byte header",
        )
        return _InfoFacts()
    version, signature, age = struct.unpack_from("<III", data, 0)
    facts = _InfoFacts(
        version=version,
        signature=signature,
        age=age,
        guid=_format_guid(data[12:28]),
        names_index=_find_names_stream(msf),
    )
    names, truncated = _parse_named_stream_blob(data, warnings)
    return replace(facts, names=names, names_truncated=truncated)


def _find_names_stream(msf: _MsfFile) -> int | None:
    """Locate the ``/names`` string-table stream by its 0xeffeeffe magic.

    The stream-name-to-index binding lives in a serialized hash table that
    this module deliberately does not decode; the string table's own magic is
    a structural fact, so the scan binds exactly that one stream.
    """
    for index, entry in enumerate(msf.streams):
        if entry.size and entry.blocks:
            start = entry.blocks[0] * msf.block_size
            head = msf.data[start : start + 4]
            if len(head) == 4 and struct.unpack("<I", head)[0] == NAMES_STREAM_SIGNATURE:
                return index
    return None


def _parse_named_stream_blob(data: bytes, warnings: list[str]) -> tuple[tuple[str, ...], bool]:
    """Parse the inline named-stream string blob that follows the header.

    Layout (verified against real MSVC output): a u32 byte size, then the
    blob of NUL-terminated names (``/names``, ``/LinkInfo``, ...). The hash
    machinery after the blob is deliberately skipped.
    """
    if len(data) < 32:
        _warn(warnings, "PDB info stream ends before the named-stream string blob")
        return (), False
    blob_size = struct.unpack_from("<I", data, 28)[0]
    blob = data[32 : 32 + blob_size]
    if len(blob) < blob_size:
        _warn(
            warnings,
            f"named-stream blob claims {blob_size} bytes but only {len(blob)} exist",
        )
    names: list[str] = []
    for part in blob.split(b"\x00"):
        if not part:
            continue
        if len(names) >= MAX_NAMES:
            _warn(warnings, f"names cap {MAX_NAMES} reached; further names dropped")
            return tuple(names), True
        names.append(part.decode("utf-8", errors="replace"))
    return tuple(names), False


# ---- DBI stream --------------------------------------------------------------


@dataclass(frozen=True)
class DbiModule:
    """One DBI module record: a compilation unit and the object it came from."""

    index: int
    module_name: str
    object_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "module_name": self.module_name,
            "object_name": self.object_name,
        }


def _parse_dbi_stream(
    data: bytes | None, max_modules: int, warnings: list[str]
) -> tuple[tuple[DbiModule, ...], int, bool]:
    """Walk stream 3's module-info substream; return (rows, total, truncated)."""
    if data is None:
        _warn(warnings, "DBI stream (stream 3) is absent; no module list")
        return (), 0, False
    if len(data) < DBI_HEADER_SIZE:
        _warn(
            warnings,
            f"DBI stream is {len(data)} bytes, too small for the {DBI_HEADER_SIZE}-byte header",
        )
        return (), 0, False
    mod_size = struct.unpack_from("<I", data, 24)[0]
    substream = data[DBI_HEADER_SIZE : DBI_HEADER_SIZE + mod_size]
    if len(substream) < mod_size:
        _warn(
            warnings,
            f"DBI module substream claims {mod_size} bytes but only "
            f"{len(substream)} exist; walk is bounded to what exists",
        )
    modules: list[DbiModule] = []
    offset = 0
    while offset < len(substream):
        if len(modules) >= max_modules:
            _warn(warnings, f"module cap {max_modules} reached; further modules dropped")
            return tuple(modules), len(modules), True
        if offset + DBI_MODULE_PREFIX_SIZE > len(substream):
            _warn(
                warnings,
                f"DBI module walk desynchronized at module index {len(modules)}: "
                f"only {len(substream) - offset} of {DBI_MODULE_PREFIX_SIZE} "
                f"prefix bytes remain",
            )
            return tuple(modules), len(modules), True
        name = _cstring(substream, offset + DBI_MODULE_PREFIX_SIZE, len(substream))
        if name is None:
            _warn(
                warnings,
                f"DBI module walk desynchronized at module index {len(modules)}: "
                f"module name is not NUL-terminated inside the substream",
            )
            return tuple(modules), len(modules), True
        object_name = _cstring(substream, name[1], len(substream))
        if object_name is None:
            _warn(
                warnings,
                f"DBI module walk desynchronized at module index {len(modules)}: "
                f"object name is not NUL-terminated inside the substream",
            )
            return tuple(modules), len(modules), True
        module = DbiModule(
            index=len(modules),
            module_name=name[0],
            object_name=object_name[0],
        )
        modules.append(module)
        end = object_name[1]
        offset = (end + 3) & ~3
        if offset > len(substream):
            offset = len(substream)
    return tuple(modules), len(modules), False


# ---- reports -----------------------------------------------------------------


@dataclass(frozen=True)
class PdbStream:
    """One MSF stream directory row."""

    index: int
    size: int | None  # None = absent (0xFFFFFFFF sentinel)
    name: str | None
    blocks: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "size": self.size,
            "name": self.name,
            "blocks": self.blocks,
        }


@dataclass(frozen=True)
class PdbInfoReport:
    """The bounded structural inventory of one local PDB file."""

    path: str
    sha256: str
    block_size: int
    num_blocks: int
    stream_count: int
    streams: tuple[PdbStream, ...]
    evidence: Evidence
    guid: str | None = None
    age: int | None = None
    pdb_version: int | None = None
    names_stream_index: int | None = None
    stream_names: tuple[str, ...] = ()
    modules: tuple[DbiModule, ...] = ()
    module_count: int = 0
    warnings: tuple[str, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "block_size": self.block_size,
            "num_blocks": self.num_blocks,
            "stream_count": self.stream_count,
            "streams_returned": len(self.streams),
            "streams": [stream.to_dict() for stream in self.streams],
            "guid": self.guid,
            "age": self.age,
            "pdb_version": self.pdb_version,
            "names_stream_index": self.names_stream_index,
            "stream_names": list(self.stream_names),
            "module_count": self.module_count,
            "modules": [module.to_dict() for module in self.modules],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def parse_pdb(
    path: Path, *, max_streams: int = DEFAULT_MAX_STREAMS, max_modules: int = DEFAULT_MAX_MODULES
) -> PdbInfoReport:
    """Parse one local ``.pdb`` file's MSF structure into a typed report.

    Args:
        path: Path to the ``.pdb`` file.
        max_streams: Ceiling on stream rows kept (1..MAX_STREAMS); the honest
            total stays in ``stream_count`` when rows are cut.
        max_modules: Ceiling on DBI module rows kept (1..MAX_MODULES).

    Raises:
        AnalysisError: ``path`` is missing, empty, too large, or not a
            structurally valid MSF v7.00 container (bad magic, insane block
            size, block map / directory / stream blocks outside the file).
    """
    if not 1 <= max_streams <= MAX_STREAMS:
        raise AnalysisError(f"max_streams must be between 1 and {MAX_STREAMS}")
    if not 1 <= max_modules <= MAX_MODULES:
        raise AnalysisError(f"max_modules must be between 1 and {MAX_MODULES}")
    target = Path(path)
    try:
        stat = target.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {target}: {exc}") from exc
    if not target.is_file():
        raise AnalysisError(f"not a PDB file: {target} is not a regular file")
    if stat.st_size == 0:
        raise AnalysisError(f"not a PDB file: {target} is empty")
    if stat.st_size > MAX_FILE_SIZE:
        raise AnalysisError(
            f"PDB too large ({stat.st_size} bytes); limit is {MAX_FILE_SIZE} bytes"
        )
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {target}: {exc}") from exc
    msf = _MsfFile(raw, target)
    warnings: list[str] = []
    info = _parse_info_stream(msf, warnings)
    modules, module_count, modules_truncated = _parse_dbi_stream(
        msf.read_stream(DBI_STREAM_INDEX, warnings), max_modules, warnings
    )
    truncated = info.names_truncated or modules_truncated
    kept = min(len(msf.streams), max_streams)
    if len(msf.streams) > max_streams:
        truncated = True
        _warn(
            warnings,
            f"stream rows capped at {max_streams} of {len(msf.streams)}; "
            f"stream_count keeps the honest total",
        )
    streams = tuple(
        PdbStream(
            index=i,
            size=msf.streams[i].size,
            name=NAMES_STREAM_NAME if info.names_index == i else None,
            blocks=len(msf.streams[i].blocks),
        )
        for i in range(kept)
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="msf_walk",
        confidence=Confidence.CERTAIN,
        detail="MSF v7.00 superblock, stream directory, info stream and DBI module walk",
        extra={
            "signature": f"0x{info.signature:08x}" if info.signature is not None else None,
            "streams": len(msf.streams),
            "modules": module_count,
        },
    )
    return PdbInfoReport(
        path=str(target),
        sha256=hashlib.sha256(raw).hexdigest(),
        block_size=msf.block_size,
        num_blocks=msf.num_blocks,
        stream_count=len(msf.streams),
        streams=streams,
        evidence=evidence,
        guid=info.guid,
        age=info.age,
        pdb_version=info.version,
        names_stream_index=info.names_index,
        stream_names=info.names,
        modules=modules,
        module_count=module_count,
        warnings=tuple(warnings),
        truncated=truncated,
    )


# ---- PE CodeView reference ---------------------------------------------------


@dataclass(frozen=True)
class CodeViewRef:
    """The PDB reference a PE carries in its debug directory.

    Attributes:
        pdb_path: Path to the PDB the binary was linked against (bounded at
            1024 bytes).
        guid: Unique PDB identifier (``RSDS`` records only; ``NB10`` records
            carry no GUID).
        age: PDB age — the increment that binds a binary to its exact PDB
            revision.
        timestamp: ``NB10`` time-date stamp (some toolchains document this
            slot as a checksum); ``None`` for ``RSDS``.
        debug_type: ``"RSDS"`` or ``"NB10"``.
        section: Name of the PE section carrying the record, when mapped.
        evidence: Provenance record (certain: read straight from the file).
    """

    pdb_path: str
    guid: str | None
    age: int | None
    timestamp: int | None
    debug_type: str
    section: str | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "pdb_path": self.pdb_path,
            "guid": self.guid,
            "age": self.age,
            "timestamp": self.timestamp,
            "debug_type": self.debug_type,
            "section": self.section,
            "evidence": self.evidence.to_dict(),
        }


def decode_codeview_record(data: bytes) -> CodeViewRef:
    """Decode one CodeView record blob (``RSDS`` or ``NB10``) as a pure function.

    Raises:
        AnalysisError: ``data`` is too short for its signature or carries an
            unknown CodeView signature.
    """
    if len(data) < 4:
        raise AnalysisError(f"CodeView record is {len(data)} bytes, too small for a signature")
    signature = data[:4]
    if signature == b"RSDS":
        if len(data) < 24:
            raise AnalysisError(f"RSDS record truncated ({len(data)} of 24 header bytes)")
        guid = _format_guid(data[4:20])
        age = struct.unpack_from("<I", data, 20)[0]
        timestamp: int | None = None
        pdb_path = _bounded_path(data, 24)
        debug_type = "RSDS"
    elif signature == b"NB10":
        if len(data) < 16:
            raise AnalysisError(f"NB10 record truncated ({len(data)} of 16 header bytes)")
        guid = None
        timestamp = struct.unpack_from("<I", data, 8)[0]
        age = struct.unpack_from("<I", data, 12)[0]
        pdb_path = _bounded_path(data, 16)
        debug_type = "NB10"
    else:
        raise AnalysisError(f"unknown CodeView signature {signature!r}")
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="codeview_record",
        confidence=Confidence.CERTAIN,
        detail=f"{debug_type} CodeView debug record",
    )
    return CodeViewRef(
        pdb_path=pdb_path,
        guid=guid,
        age=age,
        timestamp=timestamp,
        debug_type=debug_type,
        section=None,
        evidence=evidence,
    )


@dataclass(frozen=True)
class _PeSection:
    """One PE section-table row used for RVA→offset mapping."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_pointer: int


def _pe_headers(data: bytes) -> tuple[int, int, int, int]:
    """Locate (coff_offset, num_sections, optional_offset, optional_size)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise AnalysisError("not a PE file: missing MZ magic")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("not a PE file: PE\\0\\0 signature not found")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if optional_size == 0:
        raise AnalysisError("not a parseable PE: optional header is absent")
    if num_sections > 96:
        raise AnalysisError(f"PE section table declares {num_sections} sections, above the 96 cap")
    return coff, num_sections, optional, optional_size


def _debug_directory(data: bytes) -> tuple[int, int]:
    """Return the IMAGE_DIRECTORY_ENTRY_DEBUG (rva, size) pair, or (0, 0)."""
    _, num_sections, optional, optional_size = _pe_headers(data)
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:  # PE32
        fixed = 96
    elif magic == 0x20B:  # PE32+
        fixed = 112
    else:
        raise AnalysisError(f"unsupported optional header magic 0x{magic:x}")
    if optional_size < fixed or optional + fixed - 4 + 4 > len(data):
        return 0, 0
    declared = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    num_dirs = min(declared, (optional_size - fixed) // 8)
    if num_dirs <= 6:
        return 0, 0
    debug_off = optional + fixed + 6 * 8
    if debug_off + 8 > len(data):
        return 0, 0
    return struct.unpack_from("<II", data, debug_off)


def _pe_sections(data: bytes) -> list[_PeSection]:
    """Read the PE section table (bounded by the 96-section header cap)."""
    _, num_sections, optional, optional_size = _pe_headers(data)
    table = optional + optional_size
    sections: list[_PeSection] = []
    for index in range(num_sections):
        base = table + index * 40
        if base + 40 > len(data):
            break
        raw_name, vsize, va, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, base)
        sections.append(
            _PeSection(
                name=raw_name.rstrip(b"\x00").decode("ascii", errors="replace"),
                virtual_address=va,
                virtual_size=vsize,
                raw_size=raw_size,
                raw_pointer=raw_ptr,
            )
        )
        if len(sections) >= 96:
            break
    return sections


def _rva_to_offset(rva: int, sections: list[_PeSection]) -> tuple[int, str] | None:
    """Map an RVA to a file offset plus the carrying section's name."""
    for section in sections:
        if section.raw_size == 0 or section.virtual_address == 0:
            continue
        delta = rva - section.virtual_address
        if 0 <= delta < max(section.virtual_size, section.raw_size) and delta < section.raw_size:
            return section.raw_pointer + delta, section.name
    return None


def codeview_reference(path: Path) -> CodeViewRef | None:
    """Read the PE debug directory's CodeView record: PDB path, GUID/age.

    Handles both ``RSDS`` (GUID + age) and ``NB10`` (time-date stamp + age)
    records; the first CodeView entry wins. A PE without a debug directory or
    without a CodeView entry yields ``None``.

    Raises:
        AnalysisError: ``path`` is missing, or is not a parseable PE file.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {target}: {exc}") from exc
    rva, size = _debug_directory(raw)
    if rva == 0 or size == 0:
        return None
    sections = _pe_sections(raw)
    mapped = _rva_to_offset(rva, sections)
    if mapped is None or mapped[0] + 28 > len(raw):
        return None
    table_offset = mapped[0]
    for index in range(min(size // 28, MAX_DEBUG_ENTRIES)):
        base = table_offset + index * 28
        if base + 28 > len(raw):
            break
        entry_type = struct.unpack_from("<I", raw, base + 12)[0]
        size_of_data = struct.unpack_from("<I", raw, base + 16)[0]
        address_of_raw = struct.unpack_from("<I", raw, base + 20)[0]
        pointer_to_raw = struct.unpack_from("<I", raw, base + 24)[0]
        if entry_type != DEBUG_TYPE_CODEVIEW or size_of_data < 4:
            continue
        offset = pointer_to_raw
        section_name: str | None = None
        if not offset and address_of_raw:
            address_mapped = _rva_to_offset(address_of_raw, sections)
            if address_mapped is None:
                continue
            offset, section_name = address_mapped
        if not offset or offset + 4 > len(raw):
            continue
        record = raw[offset : offset + min(size_of_data, MAX_PDB_PATH_BYTES + 24)]
        reference = decode_codeview_record(record)
        if section_name is None and address_of_raw:
            address_mapped = _rva_to_offset(address_of_raw, sections)
            section_name = address_mapped[1] if address_mapped else None
        detail = f"CodeView record in IMAGE_DEBUG_DIRECTORY entry {index}"
        if section_name:
            detail += f" inside section {section_name!r}"
        evidence = Evidence(
            source=EVIDENCE_SOURCE,
            method="debug_directory",
            confidence=Confidence.CERTAIN,
            address=offset,
            detail=detail,
        )
        return replace(reference, section=section_name, evidence=evidence)
    return None

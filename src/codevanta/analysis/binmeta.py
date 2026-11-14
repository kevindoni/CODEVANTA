"""Pure-Python format metadata inspectors for CODEVANTA.

An auto-detecting :func:`inspect_metadata` entry point plus one typed
detector per format (each returns ``None`` when the format does not match):

* APK Signing Block v2/v3 (+ v1 ``META-INF/MANIFEST.MF`` presence): block
  size, signer counts, digest algorithms, min/max SDK. Certificates are
  never parsed or trusted beyond the fact of their presence.
* Go build info (magic ``\\xff Go buildinf:`` in PE/ELF): Go version,
  module path, bounded dependency list (32).
* Rust cargo-auditable (ELF note owner ``AUDITABLE`` / ``rust-audit`` or
  the ``.dep-v0`` payload): bounded crate list (32); the payload may be
  plain or zlib-compressed JSON.
* Python ``.pyc`` header (PEP 552, Python 3.7-3.13): magic number, flags,
  timestamp or source hash. Bytecode is never unmarshalled.
* Electron fuses (sentinel ``dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX``): fuse
  list with on/off/removed states (32).
* ELF notes (``PT_NOTE`` + ``SHT_NOTE``, 32) and Linux kernel-module
  ``.modinfo`` keys (64, ``ET_REL``).
* Erlang BEAM (``FOR1``/``BEAM`` IFF container): bounded chunk table
  (32) and compile-info atoms when the ``c`` chunk parses.
* Unity IL2CPP global metadata (magic ``0xFAB11BAF``, versions 24/27/
  29/31/39): native-endian header table walk with derived string, event,
  field and type counts.
* Flutter/Dart AOT snapshots (``kDartVmSnapshotData`` /
  ``kDartIsolateSnapshotData`` magic strings): snapshot kinds present
  with bounded offsets.
* HarmonyOS HAP (a ZIP carrying ``pack.info``): entry count, bounded
  ``pack.info`` summary and module count.
* CUDA fatbin (magic ``0xBA55ED50``): version, header/data size and the
  bounded ELF/PTX entry walk.
* Desktop app classification (bounded walk: 2000 files, depth 4):
  Unity, IL2CPP, Unreal (``.pak``), Electron (``app.asar``), .NET
  (CLR header directory entry).

Every finding carries :class:`~codevanta.evidence.models.Evidence` with a
``meta.*`` source id; ``high`` confidence marks magic-verified parses.
Malformed inputs raise :class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

import json
import os
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

# ---- bounded-output ceilings (house style) ---------------------------------
MAX_GO_DEPS = 32
MAX_CARGO_CRATES = 32
MAX_FUSES = 32
MAX_ELF_NOTES = 32
MAX_MODINFO_KEYS = 64
MAX_MODINFO_VALUE_CHARS = 200
MAX_DESKTOP_FILES = 2000
MAX_DESKTOP_DEPTH = 4
MAX_DESKTOP_KEY_FILES = 32
MAX_DESKTOP_PE_PROBES = 32
MAX_APK_SIGNERS = 64
MAX_APK_PAIRS = 64
MAX_ELF_SECTIONS = 512
MAX_ELF_SEGMENTS = 128
MAX_ELF_NOTE_BYTES = 4096
MAX_SECTION_READ = 1 << 20
MAX_STRING_BYTES = 4096
#: Never read more than this many bytes from any single file.
MAX_FILE_BYTES = 256 * 1024 * 1024
READ_CHUNK = 1 << 20
#: BEAM chunks kept from one IFF chunk table (bounded work).
MAX_BEAM_CHUNKS = 32
#: BEAM compile-info atoms kept from one ``c`` chunk (bounded work).
MAX_BEAM_ATOMS = 16
#: IL2CPP header (offset, size) table pairs kept (bounded work).
MAX_IL2CPP_TABLES = 32
#: Flutter snapshot magic hits kept per snapshot kind (bounded work).
MAX_FLUTTER_OFFSETS = 4
#: HAP zip entry names and JSON summary characters kept (bounded work).
MAX_HAP_ENTRIES = 64
MAX_HAP_INFO_CHARS = 2000
#: CUDA fatbin ELF/PTX entries walked from one container (bounded work).
MAX_CUDA_ENTRIES = 8

# ---- format constants -------------------------------------------------------
GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
PYC_MAGIC_MIN = 3300
PYC_MAGIC_MAX = 3600
#: Final per-release ``.pyc`` magic numbers for Python 3.7-3.13 (PEP 552 era).
PYC_MAGIC_VERSIONS: dict[int, str] = {
    3394: "3.7",
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3571: "3.13",
}
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_BLOCK_ID_V2 = 0x7109871A
APK_BLOCK_ID_V3 = 0xF05368C0
APK_BLOCK_ID_V3_1 = 0x1B93AD61
APK_DIGEST_NAMES: dict[int, str] = {
    0x0101: "RSA-PKCS1-SHA256",
    0x0102: "RSA-PKCS1-SHA512",
    0x0103: "RSA-PSS-SHA256",
    0x0104: "RSA-PSS-SHA512",
    0x0105: "ECDSA-SHA256",
    0x0106: "ECDSA-SHA512",
    0x0107: "DSA-SHA256",
    0x0108: "DSA-SHA512",
    0x0421: "RSA-PKCS1-SHA256-verity",
    0x0422: "RSA-PSS-SHA256-verity",
    0x0423: "ECDSA-SHA256-verity",
    0x0424: "DSA-SHA256-verity",
    0x0425: "ECDSA-SHA512-verity",
}
ELECTRON_FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
#: V1 fuse-wire order per Electron ``build/fuses/fuses.json5``.
ELECTRON_FUSE_NAMES_V1: tuple[str, ...] = (
    "run_as_node",
    "cookie_encryption",
    "node_options",
    "node_cli_inspect",
    "embedded_asar_integrity_validation",
    "only_load_app_from_asar",
    "load_browser_process_specific_v8_snapshot",
    "grant_file_protocol_extra_privileges",
    "wasm_trap_handlers",
)
#: ``0x30`` = off, ``0x31`` = on, ``0x72`` = removed (Electron fuse wire).
ELECTRON_FUSE_STATES: dict[int, str] = {0x30: "off", 0x31: "on", 0x72: "removed"}
CARGO_AUDIT_NOTE_OWNERS = ("AUDITABLE", "rust-audit")
CARGO_AUDIT_SECTION = ".dep-v0"
#: IL2CPP global-metadata sanity word. On disk it is little-endian
#: (``af 1b b1 fa``); big-endian writers (``fa b1 1b af``) are accepted too
#: and switch the whole header walk to big-endian ints.
IL2CPP_MAGIC = 0xFAB11BAF
#: IL2CPP metadata families this detector can name table positions for.
IL2CPP_KNOWN_VERSIONS = (24, 27, 29, 31, 39)
#: One Il2CppStringLiteral record: ``(uint32_t length, uint32_t dataIndex)``.
IL2CPP_STRING_LITERAL_STRIDE = 8
#: One Il2CppEventDefinition record: name, type, add, remove, raise, token.
IL2CPP_EVENT_STRIDE = 24
#: One Il2CppFieldDefinition record: name, type, token.
IL2CPP_FIELD_STRIDE = 12
#: One Il2CppParameterDefinition record: name, token, type.
IL2CPP_PARAM_STRIDE = 12
#: Lower bound on one Il2Cpp type-definition record: the fixed index/flags/
#: start fields every family keeps. Dividing the type-table size by this
#: yields an entry-count floor, never an over-count.
IL2CPP_TYPE_STRIDE_FLOOR = 64
#: Header pair indexes shared by the v24.1-v39 metadata families
#: (0-based, after the magic+version pair). ``parameters`` is family-specific
#: in the wild and is therefore only counted for the v24 layout this module
#: documents; the remaining tables are positionally stable.
IL2CPP_TABLE_POSITIONS: dict[str, int] = {
    "string_literals": 0,
    "string_blob": 2,
    "events": 3,
    "properties": 4,
    "methods": 5,
    "parameters": 6,
    "fields": 10,
    "type_definitions": 11,
}
#: Flutter/Dart AOT snapshot magic strings (VM and isolate snapshots).
FLUTTER_VM_MAGIC = b"kDartVmSnapshotData"
FLUTTER_ISOLATE_MAGIC = b"kDartIsolateSnapshotData"
#: HarmonyOS HAP package descriptor entry.
HAP_PACK_INFO = "pack.info"
#: CUDA fatbin container magic, little-endian on disk.
CUDA_FATBIN_MAGIC = 0xBA55ED50
#: CUDA fatbin entry kinds (fat_text_header ``kind``).
CUDA_ENTRY_KINDS: dict[int, str] = {1: "elf", 2: "ptx"}

# ---- typed results ----------------------------------------------------------


@dataclass(frozen=True)
class PycInfo:
    """PEP 552 ``.pyc`` header (Python 3.7-3.13). Bytecode is never read."""

    magic: int
    python_version: str | None
    flags: int
    hash_based: bool
    check_source: bool
    timestamp: int | None
    source_size: int | None
    source_hash: bytes | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "python_version": self.python_version,
            "flags": self.flags,
            "hash_based": self.hash_based,
            "check_source": self.check_source,
            "timestamp": self.timestamp,
            "source_size": self.source_size,
            "source_hash": self.source_hash.hex() if self.source_hash else None,
        }


@dataclass(frozen=True)
class ApkSigningInfo:
    """APK Signing Block v2/v3 summary plus v1 (JAR-style) presence."""

    v1_present: bool
    v1_signature_files: tuple[str, ...]
    v2_signer_count: int | None
    v3_signer_count: int | None
    digest_algorithms: tuple[str, ...]
    min_sdk: int | None
    max_sdk: int | None
    block_size: int | None
    evidence: tuple[Evidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "v1_present": self.v1_present,
            "v1_signature_files": list(self.v1_signature_files),
            "v2_signer_count": self.v2_signer_count,
            "v3_signer_count": self.v3_signer_count,
            "digest_algorithms": list(self.digest_algorithms),
            "min_sdk": self.min_sdk,
            "max_sdk": self.max_sdk,
            "block_size": self.block_size,
        }


@dataclass(frozen=True)
class GoBuildInfo:
    """Go ``buildinf`` blob: toolchain version, module path, dependencies."""

    go_version: str
    module_path: str | None
    module_version: str | None
    dependency_count: int
    dependencies: tuple[str, ...]
    build_settings_count: int
    layout: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "go_version": self.go_version,
            "module_path": self.module_path,
            "module_version": self.module_version,
            "dependency_count": self.dependency_count,
            "dependencies": list(self.dependencies),
            "build_settings_count": self.build_settings_count,
            "layout": self.layout,
        }


@dataclass(frozen=True)
class CargoAuditableInfo:
    """cargo-auditable dependency payload (plain or zlib-compressed JSON)."""

    crate_count: int
    crates: tuple[str, ...]
    payload_origin: str
    compressed: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "crate_count": self.crate_count,
            "crates": list(self.crates),
            "payload_origin": self.payload_origin,
            "compressed": self.compressed,
        }


@dataclass(frozen=True)
class ElectronFusesInfo:
    """Electron fuse wire: per-fuse on/off/removed states."""

    fuse_schema_version: int
    fuse_count: int
    enabled: int
    disabled: int
    removed: int
    fuses: tuple[tuple[str, str], ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "fuse_schema_version": self.fuse_schema_version,
            "fuse_count": self.fuse_count,
            "enabled": self.enabled,
            "disabled": self.disabled,
            "removed": self.removed,
            "fuses": [{"name": name, "state": state} for name, state in self.fuses],
        }


@dataclass(frozen=True)
class ElfNote:
    """One ELF note record (``PT_NOTE`` or ``SHT_NOTE``)."""

    name: str
    n_type: int
    n_type_name: str | None
    desc_hex: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": f"0x{self.n_type:08x}",
            "type_name": self.n_type_name,
            "desc_hex": self.desc_hex,
        }


@dataclass(frozen=True)
class ElfNotesInfo:
    """ELF notes from note program headers and note sections."""

    note_count: int
    note_segments: int
    note_sections: int
    build_id: str | None
    notes: tuple[ElfNote, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "note_count": self.note_count,
            "note_segments": self.note_segments,
            "note_sections": self.note_sections,
            "build_id": self.build_id,
            "notes": [note.to_dict() for note in self.notes],
        }


@dataclass(frozen=True)
class KernelModuleInfo:
    """Linux kernel module ``.modinfo`` key/value pairs (``ET_REL``)."""

    key_count: int
    modinfo: dict[str, str]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {"key_count": self.key_count, "modinfo": dict(self.modinfo)}


@dataclass(frozen=True)
class DesktopAppInfo:
    """Desktop app classification from a bounded directory walk."""

    classification: str
    frameworks: tuple[str, ...]
    key_files: tuple[str, ...]
    files_scanned: int
    scan_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "frameworks": list(self.frameworks),
            "key_files": list(self.key_files),
            "files_scanned": self.files_scanned,
            "scan_truncated": self.scan_truncated,
        }


@dataclass(frozen=True)
class BeamInfo:
    """Erlang BEAM IFF container: bounded chunk table plus compile-info atoms."""

    iff_size: int
    chunk_count: int
    chunks: tuple[tuple[str, int], ...]
    chunks_truncated: bool
    compile_info_atoms: tuple[str, ...]
    compile_info_decoded: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "iff_size": self.iff_size,
            "chunk_count": self.chunk_count,
            "chunks": [{"name": name, "size": size} for name, size in self.chunks],
            "chunks_truncated": self.chunks_truncated,
            "compile_info_atoms": list(self.compile_info_atoms),
            "compile_info_decoded": self.compile_info_decoded,
        }


@dataclass(frozen=True)
class Il2CppInfo:
    """Unity IL2CPP global-metadata header: bounded table walk and counts."""

    version: int
    known_version: bool
    endian: str
    string_count: int | None
    string_table_bytes: int | None
    event_count: int | None
    property_count: int | None
    method_table_bytes: int | None
    param_count: int | None
    field_count: int | None
    type_count_min: int | None
    table_pairs: tuple[tuple[int, int, int], ...]
    tables_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "known_version": self.known_version,
            "endian": self.endian,
            "string_count": self.string_count,
            "string_table_bytes": self.string_table_bytes,
            "event_count": self.event_count,
            "property_count": self.property_count,
            "method_table_bytes": self.method_table_bytes,
            "param_count": self.param_count,
            "field_count": self.field_count,
            "type_count_min": self.type_count_min,
            "table_pairs": [
                {"index": index, "offset": offset, "bytes": size}
                for index, offset, size in self.table_pairs
            ],
            "tables_truncated": self.tables_truncated,
        }


@dataclass(frozen=True)
class FlutterSnapshotInfo:
    """Flutter/Dart AOT snapshot magics found in one binary blob."""

    kinds: tuple[str, ...]
    vm_offsets: tuple[int, ...]
    isolate_offsets: tuple[int, ...]
    scan_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "kinds": list(self.kinds),
            "vm_offsets": list(self.vm_offsets),
            "isolate_offsets": list(self.isolate_offsets),
            "scan_truncated": self.scan_truncated,
        }


@dataclass(frozen=True)
class HapInfo:
    """HarmonyOS HAP: a zip carrying ``pack.info``."""

    entry_count: int
    entry_names: tuple[str, ...]
    entries_truncated: bool
    module_count: int | None
    pack_info_summary: str | None
    pack_info_decoded: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_count": self.entry_count,
            "entry_names": list(self.entry_names),
            "entries_truncated": self.entries_truncated,
            "module_count": self.module_count,
            "pack_info_summary": self.pack_info_summary,
            "pack_info_decoded": self.pack_info_decoded,
        }


@dataclass(frozen=True)
class CudaFatbinInfo:
    """CUDA fatbin container: header fields plus the bounded entry walk."""

    version: int
    header_size: int
    data_size: int
    entry_count: int
    elf_count: int
    ptx_count: int
    kinds: tuple[str, ...]
    entries_truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "header_size": self.header_size,
            "data_size": self.data_size,
            "entry_count": self.entry_count,
            "elf_count": self.elf_count,
            "ptx_count": self.ptx_count,
            "kinds": list(self.kinds),
            "entries_truncated": self.entries_truncated,
        }


@dataclass(frozen=True)
class MetadataReport:
    """Auto-detected format metadata for one path."""

    path: str
    kind: str
    details: dict[str, Any]
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "details": self.details,
            "evidence": [item.to_dict() for item in self.evidence],
        }


# ---- low-level bounded I/O helpers ------------------------------------------


def _checked_size(path: Path) -> int:
    """Return the file size, refusing empty and over-budget files."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AnalysisError(f"cannot stat {path}: {exc}") from exc
    if size == 0:
        raise AnalysisError(f"empty file: {path}")
    if size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"{path} exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB read budget"
        )
    return size


def _open_file(path: Path) -> Any:
    try:
        return path.open("rb")
    except OSError as exc:
        raise AnalysisError(f"cannot read {path}: {exc}") from exc


def _read_slice(handle: Any, offset: int, length: int) -> bytes:
    """Bounded ``seek``+``read``; short reads are tolerated."""
    if offset < 0 or length <= 0:
        return b""
    handle.seek(offset)
    return handle.read(length)


def _note(warnings: list[str], message: str) -> None:
    """Append one bounded advisory to a detector's warning list."""
    if len(warnings) < 8:
        warnings.append(message)


def _join_notes(detail: str, warnings: list[str]) -> str:
    """Fold up to two detector advisories into one evidence detail line."""
    if not warnings:
        return detail
    extra = "; ".join(warnings[:2])
    if len(warnings) > 2:
        extra += f"; +{len(warnings) - 2} more"
    return f"{detail}; {extra}"


def _hex_preview(data: bytes, limit: int = 32) -> str:
    """Bounded hex rendering of a note descriptor."""
    return data[:limit].hex()


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    if offset + 4 > len(data):
        raise AnalysisError("truncated 32-bit field")
    return int(struct.unpack_from(endian + "I", data, offset)[0])


def _u64(data: bytes, offset: int, endian: str = "<") -> int:
    if offset + 8 > len(data):
        raise AnalysisError("truncated 64-bit field")
    return int(struct.unpack_from(endian + "Q", data, offset)[0])


def _read_cstr(blob: bytes, offset: int) -> str:
    """Read one NUL-terminated string, bounded by :data:`MAX_STRING_BYTES`."""
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset, offset + MAX_STRING_BYTES)
    if end == -1:
        raise AnalysisError("unterminated string in metadata blob")
    return blob[offset:end].decode("utf-8", errors="replace")


def _chunked_find(handle: Any, size: int, needle: bytes) -> int | None:
    """Find ``needle`` in the whole file using bounded overlapping chunks."""
    overlap = len(needle) - 1
    pos = 0
    while pos < size:
        end = min(size, pos + READ_CHUNK)
        data = _read_slice(handle, pos, end - pos)
        idx = data.find(needle)
        if idx != -1:
            return pos + idx
        if end >= size:
            break
        pos = end - overlap if end - overlap > pos else end
    return None


# ---- minimal container parsers (ELF / PE) -----------------------------------


@dataclass(frozen=True)
class _Section:
    name: str
    sh_type: int
    offset: int
    size: int


@dataclass(frozen=True)
class _NoteSource:
    """File range that holds note records (segment or section backed)."""

    offset: int
    size: int
    origin: str


@dataclass(frozen=True)
class _Container:
    """Minimal ELF/PE structure info shared by the detectors."""

    fmt: str
    endian: str
    sections: tuple[_Section, ...]
    note_sources: tuple[_NoteSource, ...]
    va_ranges: tuple[tuple[int, int, int], ...]  # (vaddr, file_offset, filesz)


def _parse_elf(handle: Any, size: int) -> _Container | None:
    ident = _read_slice(handle, 0, 16)
    if len(ident) < 16 or ident[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = ident[4], ident[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise AnalysisError("malformed ELF identification bytes")
    endian = "<" if ei_data == 1 else ">"
    wide = ei_class == 2
    head_fmt = endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH")
    head_size = 64 if wide else 52
    head = _read_slice(handle, 16, head_size - 16)
    if len(head) < head_size - 16:
        raise AnalysisError("truncated ELF header")
    fields = struct.unpack(head_fmt, head)
    e_phoff = int(fields[4])
    e_shoff = int(fields[5])
    e_phentsize = int(fields[8])
    e_phnum = int(fields[9])
    e_shentsize = int(fields[10])
    e_shnum = int(fields[11])
    e_shstrndx = int(fields[12])

    sections: list[_Section] = []
    note_sources: list[_NoteSource] = []
    va_ranges: list[tuple[int, int, int]] = []

    # Program headers first so PT_NOTE notes precede section notes (ELF
    # layout order).
    if e_phoff and e_phnum and e_phnum <= MAX_ELF_SEGMENTS and e_phentsize:
        for idx in range(e_phnum):
            raw = _read_slice(handle, e_phoff + idx * e_phentsize, e_phentsize)
            if wide and len(raw) >= 56:
                p_type, _, p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack(
                    endian + "IIQQQQQQ", raw[:56]
                )
            elif not wide and len(raw) >= 32:
                p_type, p_off, p_vaddr, _, p_filesz, _, _, _ = struct.unpack(
                    endian + "IIIIIIII", raw[:32]
                )
            else:
                break
            if p_type == 4 and 0 < p_filesz <= MAX_SECTION_READ:
                note_sources.append(_NoteSource(int(p_off), int(p_filesz), "PT_NOTE"))
            if p_type == 1 and 0 < p_filesz:
                va_ranges.append((int(p_vaddr), int(p_off), int(p_filesz)))

    if e_shoff and e_shnum and e_shnum <= MAX_ELF_SECTIONS and e_shentsize:
        strtab = b""
        if 0 < e_shstrndx < e_shnum:
            sh = _read_slice(handle, e_shoff + e_shstrndx * e_shentsize, e_shentsize)
            need = 40 if wide else 24
            if len(sh) >= need:
                sh_fields = struct.unpack(
                    endian + ("IIQQQQ" if wide else "IIIIII"), sh[:need]
                )
                sh_off, sh_size = int(sh_fields[4]), int(sh_fields[5])
                if 0 < sh_size <= MAX_SECTION_READ:
                    strtab = _read_slice(handle, sh_off, sh_size)
        sect_need = 40 if wide else 24
        for idx in range(e_shnum):
            raw = _read_slice(handle, e_shoff + idx * e_shentsize, e_shentsize)
            if len(raw) < sect_need:
                break
            sh_name, sh_type, _, _, sh_off, sh_size = struct.unpack(
                endian + ("IIQQQQ" if wide else "IIIIII"), raw[:sect_need]
            )
            name = ""
            if strtab and sh_name < len(strtab):
                stop = strtab.find(b"\0", sh_name)
                stop = stop if stop != -1 else len(strtab)
                name = strtab[sh_name:stop].decode("utf-8", errors="replace")
            sections.append(_Section(name, int(sh_type), int(sh_off), int(sh_size)))
            if sh_type == 7 and 0 < sh_size <= MAX_SECTION_READ:
                note_sources.append(_NoteSource(int(sh_off), int(sh_size), name))

    _ = size
    return _Container(
        "ELF", endian, tuple(sections), tuple(note_sources), tuple(va_ranges)
    )


def _parse_pe(handle: Any, size: int) -> _Container | None:
    dos = _read_slice(handle, 0, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return None
    e_lfanew = int(struct.unpack_from("<I", dos, 0x3C)[0])
    coff = _read_slice(handle, e_lfanew, 24)
    if len(coff) < 24 or coff[:4] != b"PE\0\0":
        raise AnalysisError("malformed PE header (bad PE signature)")
    num_sections = int(struct.unpack_from("<H", coff, 6)[0])
    opt_size = int(struct.unpack_from("<H", coff, 20)[0])
    opt = _read_slice(handle, e_lfanew + 24, opt_size)
    if len(opt) < 2:
        raise AnalysisError("malformed PE header (missing optional header)")
    magic = int(struct.unpack_from("<H", opt, 0)[0])
    if magic == 0x20B:
        image_base = _u64(opt, 24)
    elif magic == 0x10B:
        image_base = _u32(opt, 28)
    else:
        raise AnalysisError(f"unknown PE optional-header magic 0x{magic:04x}")
    sections: list[_Section] = []
    va_ranges: list[tuple[int, int, int]] = []
    for idx in range(min(num_sections, MAX_ELF_SEGMENTS)):
        body = _read_slice(handle, e_lfanew + 24 + opt_size + idx * 40, 40)
        if len(body) < 40:
            break
        name = body[:8].rstrip(b"\0").decode("utf-8", errors="replace")
        vsize, va, rawsize, raw_ptr = struct.unpack("<IIII", body[8:24])
        sections.append(_Section(name, 0, raw_ptr, rawsize))
        if rawsize:
            va_ranges.append((image_base + va, raw_ptr, min(rawsize, vsize or rawsize)))
    _ = size
    return _Container("PE", "<", tuple(sections), (), tuple(va_ranges))


def _open_container(handle: Any, size: int) -> _Container | None:
    head = _read_slice(handle, 0, 4)
    if head[:4] == b"\x7fELF":
        return _parse_elf(handle, size)
    if head[:2] == b"MZ":
        return _parse_pe(handle, size)
    return None


def _read_va_cstr(handle: Any, container: _Container, address: int) -> str:
    """Resolve a virtual address to file bytes and read one NUL string."""
    for vaddr, offset, filesz in container.va_ranges:
        if vaddr <= address < vaddr + filesz:
            blob = _read_slice(handle, offset + (address - vaddr), MAX_STRING_BYTES)
            return _read_cstr(blob, 0)
    raise AnalysisError(f"Go build info address 0x{address:x} is not mapped")


# ---- Python .pyc (PEP 552) ---------------------------------------------------


def detect_pyc(path: str | Path) -> PycInfo | None:
    """Inspect a ``.pyc`` header (Python 3.7-3.13). ``None`` when not a pyc."""
    p = Path(path)
    if p.is_dir():
        return None
    _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 16)
    if len(head) < 4:
        return None
    magic = int(struct.unpack_from("<H", head, 0)[0])
    if head[2:4] != b"\r\n" or not (PYC_MAGIC_MIN <= magic <= PYC_MAGIC_MAX):
        return None
    if len(head) < 16:
        raise AnalysisError("truncated .pyc header (need 16 bytes)")
    flags = _u32(head, 4)
    hash_based = bool(flags & 0x1)
    check_source = bool(flags & 0x2)
    timestamp: int | None = None
    source_size: int | None = None
    source_hash: bytes | None = None
    if hash_based:
        source_hash = head[8:16]
    else:
        timestamp = _u32(head, 8)
        source_size = _u32(head, 12)
    evidence = Evidence(
        source="meta.pyc",
        method="pep552-header",
        confidence=Confidence.HIGH,
        detail=f"magic {magic} ({PYC_MAGIC_VERSIONS.get(magic, 'unknown release')})",
        extra={"header_hex": head.hex()},
    )
    return PycInfo(
        magic=magic,
        python_version=PYC_MAGIC_VERSIONS.get(magic),
        flags=flags,
        hash_based=hash_based,
        check_source=check_source,
        timestamp=timestamp,
        source_size=source_size,
        source_hash=source_hash,
        evidence=evidence,
    )


# ---- APK Signing Block v1/v2/v3 ----------------------------------------------


def _apk_eocd(handle: Any, size: int) -> int:
    """Locate the End Of Central Directory record offset (bounded tail scan)."""
    window = min(size, READ_CHUNK)
    tail = _read_slice(handle, size - window, window)
    idx = tail.rfind(b"PK\x05\x06")
    if idx == -1 or idx + 22 > len(tail):
        raise AnalysisError("truncated zip archive (no End Of Central Directory)")
    return size - window + idx


def _apk_signer_block(value: bytes, version: int) -> tuple[int, list[int], int | None, int | None]:
    """Parse one v2/v3 ID-value payload: (count, digest algs, min SDK, max SDK).

    Length-prefixed signer sequence; each signer's signed data holds the
    digest records. Certificates and signatures are never parsed or
    extracted - only the digest algorithm IDs are read.
    """
    seq_len = _u32(value, 0)
    end = 4 + seq_len
    if end > len(value):
        raise AnalysisError("malformed APK signer sequence length")
    pos = 4
    count = 0
    algs: list[int] = []
    min_sdk: int | None = None
    max_sdk: int | None = None
    while pos + 4 <= end:
        slen = _u32(value, pos)
        if slen < 4 or pos + 4 + slen > end:
            raise AnalysisError("truncated APK signer record")
        count += 1
        if count > MAX_APK_SIGNERS:
            raise AnalysisError(f"more than {MAX_APK_SIGNERS} APK signers")
        signer = value[pos + 4 : pos + 4 + slen]
        sd_len = _u32(signer, 0)
        if sd_len < 4 or 4 + sd_len > len(signer):
            raise AnalysisError("truncated APK signed-data")
        sd = signer[4 : 4 + sd_len]
        dg_len = _u32(sd, 0)
        if 4 + dg_len > len(sd):
            raise AnalysisError("truncated APK digest list")
        digests = sd[4 : 4 + dg_len]
        dpos = 0
        while dpos + 4 <= len(digests):
            rec_len = _u32(digests, dpos)
            if dpos + 4 + rec_len > len(digests):
                raise AnalysisError("truncated APK digest record")
            if rec_len >= 4:
                algs.append(_u32(digests, dpos + 4))
            dpos += 4 + rec_len
        cpos = 4 + dg_len
        certs_len = _u32(sd, cpos)
        cpos += 4 + certs_len
        attrs_len = _u32(sd, cpos)
        cpos += 4 + attrs_len
        if version == 3:
            if cpos + 8 > len(sd):
                raise AnalysisError("v3 signed data missing min/max SDK")
            min_sdk = _u32(sd, cpos)
            max_sdk = _u32(sd, cpos + 4)
        pos += 4 + slen
    return count, algs, min_sdk, max_sdk


def _apk_parse_block(handle: Any, start: int, declared: int) -> dict[str, Any]:
    """Walk the ID-value pairs of the APK Signing Block (bounded).

    ``declared`` is the size-of-block value (excludes the leading 8-byte
    field, includes the trailing size field and the 16-byte magic), and
    ``start`` is the file offset of the leading size field.
    """
    if declared > MAX_SECTION_READ * 32:
        raise AnalysisError("APK Signing Block too large to parse")
    if declared < 24:
        raise AnalysisError("malformed APK Signing Block (size < 24)")
    blob = _read_slice(handle, start, declared + 8)
    if len(blob) < declared + 8:
        raise AnalysisError("truncated APK Signing Block")
    if _u64(blob, 0) != declared:
        raise AnalysisError("malformed APK Signing Block (size field mismatch)")
    if _u64(blob, declared - 16) != declared:
        raise AnalysisError("malformed APK Signing Block (footer size mismatch)")
    if blob[declared - 8 : declared + 8] != APK_SIG_BLOCK_MAGIC:
        raise AnalysisError("malformed APK Signing Block (bad trailing magic)")
    pos = 8  # skip the leading size-of-block field
    end = declared - 16  # exclude the trailing size field and the magic
    pairs = 0
    out: dict[str, Any] = {"v2_count": None, "v3_count": None, "algs": []}
    while pos + 12 <= end:
        plen = _u64(blob, pos)
        if plen < 4 or pos + 8 + plen > end:
            raise AnalysisError("malformed APK Signing Block pair")
        pair_id = _u32(blob, pos + 8)
        value = blob[pos + 12 : pos + 8 + plen]
        if pair_id == APK_BLOCK_ID_V2:
            count, algs, _, _ = _apk_signer_block(value, version=2)
            out["v2_count"] = count
            out["algs"].extend(algs)
        elif pair_id in (APK_BLOCK_ID_V3, APK_BLOCK_ID_V3_1):
            count, algs, mn, mx = _apk_signer_block(value, version=3)
            out["v3_count"] = count
            out["algs"].extend(algs)
            out.setdefault("min_sdk", mn)
            out.setdefault("max_sdk", mx)
        pairs += 1
        if pairs > MAX_APK_PAIRS:
            raise AnalysisError(f"more than {MAX_APK_PAIRS} signing-block pairs")
        pos += 8 + plen
    return out


def detect_apk_signing(path: str | Path) -> ApkSigningInfo | None:
    """Inspect APK signing metadata (v1 manifest, v2/v3 block).

    ``None`` when the file is not a zip-family archive. Certificates are
    never trusted or extracted: only digest algorithm IDs are read.
    """
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        lead = _read_slice(handle, 0, 4)
        if lead[:2] != b"PK":
            return None
        eocd = _apk_eocd(handle, size)
        tail = _read_slice(handle, eocd, 24)
        if len(tail) < 22:
            raise AnalysisError("truncated End Of Central Directory record")
        cd_offset = _u32(tail, 16)
        if cd_offset == 0xFFFFFFFF:
            raise AnalysisError("zip64 APK archives are not supported")
        if cd_offset >= size:
            raise AnalysisError("EOCD central-directory offset points outside the file")

        block_size: int | None = None
        parsed: dict[str, Any] = {}
        if cd_offset >= 32:
            footer = _read_slice(handle, cd_offset - 24, 24)
            if footer[8:24] == APK_SIG_BLOCK_MAGIC:
                declared = _u64(footer, 0)
                start = cd_offset - declared - 8
                if start < 0:
                    raise AnalysisError("malformed APK Signing Block (before zip start)")
                block_size = declared
                parsed = _apk_parse_block(handle, start, declared)

    v1_present = False
    v1_files: list[str] = []
    try:
        with zipfile.ZipFile(p) as archive:
            names = archive.namelist()
            v1_present = "META-INF/MANIFEST.MF" in names
            v1_files = [
                name
                for name in names
                if name.startswith("META-INF/")
                and name.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))
            ][:8]
    except zipfile.BadZipFile as exc:
        raise AnalysisError(f"malformed zip archive: {exc}") from exc

    if block_size is None and not v1_present:
        return None
    evidence: list[Evidence] = []
    if block_size is not None:
        evidence.append(
            Evidence(
                source="meta.apk.sigblock",
                method="apk-signing-block-footer",
                confidence=Confidence.HIGH,
                detail=f"block size {block_size} bytes before central directory",
                extra={"magic": APK_SIG_BLOCK_MAGIC.decode("ascii")},
            )
        )
    if v1_present:
        evidence.append(
            Evidence(
                source="meta.apk.v1",
                method="zip-central-directory-names",
                confidence=Confidence.HIGH if v1_files else Confidence.MEDIUM,
                detail="META-INF/MANIFEST.MF present (v1/JAR-style signing)",
                extra={"signature_files": list(v1_files)},
            )
        )
    alg_names: list[str] = []
    for alg in dict.fromkeys(parsed.get("algs", [])):
        alg_names.append(APK_DIGEST_NAMES.get(alg, f"0x{alg:04x}"))
    return ApkSigningInfo(
        v1_present=v1_present,
        v1_signature_files=tuple(v1_files),
        v2_signer_count=parsed.get("v2_count"),
        v3_signer_count=parsed.get("v3_count"),
        digest_algorithms=tuple(alg_names),
        min_sdk=parsed.get("min_sdk"),
        max_sdk=parsed.get("max_sdk"),
        block_size=block_size,
        evidence=tuple(evidence),
    )


# ---- Go build info -----------------------------------------------------------


def _parse_go_module_info(mod: str) -> tuple[str | None, str | None, list[str], int, int]:
    """Parse the Go module-info string: mod/path/dep/=>/build lines."""
    module_path: str | None = None
    module_version: str | None = None
    deps: list[str] = []
    dep_total = 0
    settings = 0
    for line in mod.split("\n"):
        if not line:
            continue
        fields = line.split("\t")
        tag = fields[0]
        if tag == "mod" and len(fields) >= 2:
            module_path = fields[1]
            if len(fields) >= 3:
                module_version = fields[2] or None
        elif tag == "path" and module_path is None and len(fields) >= 2:
            module_path = fields[1]
        elif tag == "dep":
            dep_total += 1
            if len(fields) >= 3 and len(deps) < MAX_GO_DEPS:
                deps.append(f"{fields[1]}@{fields[2]}")
        elif tag == "=>":
            # Replacement line for the immediately preceding dependency.
            if deps and len(fields) >= 3 and len(fields[1]) >= 1:
                replace = f"{fields[1]}@{fields[2]}" if len(fields) >= 3 else fields[1]
                deps[-1] += f" => {replace}"
        elif tag == "build":
            settings += 1
    return module_path, module_version, deps, dep_total, settings


def detect_go_buildinfo(path: str | Path) -> GoBuildInfo | None:
    """Find the Go ``buildinf`` magic blob in a PE/ELF. ``None`` when absent."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    vers: str | None = None
    mod: str | None = None
    layout = "unknown"
    magic_offset = -1
    with _open_file(p) as handle:
        off = _chunked_find(handle, size, GO_BUILDINFO_MAGIC)
        if off is None:
            return None
        magic_offset = off
        header = _read_slice(handle, off, 32)
        if len(header) < 16:
            raise AnalysisError("truncated Go build info header")
        ptr_size = header[14]
        if ptr_size not in (4, 8):
            raise AnalysisError(f"invalid Go build info pointer size {ptr_size}")
        flags = header[15]
        container = _open_container(handle, size)
        endian = container.endian if container else "<"
        if flags & 0x2:
            # Inline null-terminated strings. Go 1.18-1.23 places them right
            # after the 16-byte logical header; Go 1.24+ pads the header to
            # 32 bytes first. Probe both and keep the one whose first string
            # looks like a Go version.
            near = _read_slice(handle, off + 16, MAX_SECTION_READ)
            far = _read_slice(handle, off + 32, MAX_SECTION_READ)
            near_vers = _read_cstr(near, 0)
            far_vers = _read_cstr(far, 0)
            if near_vers.startswith("go"):
                vers = near_vers
                mod = _read_cstr(near, len(near_vers) + 1)
                layout = "inline-strings"
            elif far_vers.startswith("go"):
                vers = far_vers
                mod = _read_cstr(far, len(far_vers) + 1)
                layout = "inline-strings-header32"
        if vers is None or not vers.startswith("go"):
            base = 16
            need = base + 2 * ptr_size
            if len(header) < need:
                header = _read_slice(handle, off, need)
            if len(header) < need:
                raise AnalysisError("truncated Go build info pointer fields")
            order: Literal["little", "big"] = "little" if endian == "<" else "big"
            vers_addr = int.from_bytes(header[base : base + ptr_size], order)
            mod_addr = int.from_bytes(
                header[base + ptr_size : base + 2 * ptr_size], order
            )
            if container is None or not container.va_ranges:
                raise AnalysisError("Go build info pointers cannot be resolved")
            vers = _read_va_cstr(handle, container, vers_addr)
            mod = _read_va_cstr(handle, container, mod_addr)
            layout = "address-pointers"
        if not vers.startswith("go"):
            raise AnalysisError(f"malformed Go build info version {vers!r}")

    module_path, module_version, deps, dep_total, settings = _parse_go_module_info(
        mod or ""
    )
    evidence = Evidence(
        source="meta.gobuildinfo",
        method="buildinf-magic-scan",
        confidence=Confidence.HIGH,
        detail=f"magic at file offset 0x{magic_offset:x}, layout {layout}",
        extra={"go_version": vers, "layout": layout},
    )
    return GoBuildInfo(
        go_version=vers,
        module_path=module_path,
        module_version=module_version,
        dependency_count=dep_total,
        dependencies=tuple(deps),
        build_settings_count=settings,
        layout=layout,
        evidence=evidence,
    )


# ---- Rust cargo-auditable ----------------------------------------------------


def _parse_audit_payload(payload: bytes, origin: str) -> CargoAuditableInfo:
    """Decode (optionally zlib) + JSON-parse a cargo-auditable payload."""
    compressed = False
    data = payload
    try:
        decompressor = zlib.decompressobj()
        inflated = decompressor.decompress(payload, MAX_SECTION_READ)
        if inflated:
            data = inflated
            compressed = True
    except zlib.error:
        data = payload
    if not data:
        raise AnalysisError("empty cargo-auditable payload")
    if len(data) > MAX_SECTION_READ:
        raise AnalysisError("cargo-auditable payload too large")
    try:
        entries = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"malformed cargo-auditable payload: {exc}") from exc
    if not isinstance(entries, list):
        raise AnalysisError("cargo-auditable payload is not a JSON array")
    crates: list[str] = []
    for entry in entries[:MAX_CARGO_CRATES]:
        if not isinstance(entry, dict):
            raise AnalysisError("cargo-auditable entry is not a JSON object")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name:
            raise AnalysisError("cargo-auditable entry without a name")
        crates.append(f"{name}@{version}" if isinstance(version, str) else name)
    evidence = Evidence(
        source="meta.cargo-auditable",
        method="audit-note-json",
        confidence=Confidence.HIGH,
        detail=f"payload from {origin}, {'zlib' if compressed else 'plain'} JSON",
        extra={"origin": origin, "compressed": compressed},
    )
    return CargoAuditableInfo(
        crate_count=len(entries),
        crates=tuple(crates),
        payload_origin=origin,
        compressed=compressed,
        evidence=evidence,
    )


def _elf_audit_payload(
    handle: Any, container: _Container
) -> tuple[bytes, str] | None:
    """Extract the audit payload from an ELF note or the ``.dep-v0`` section."""
    for source in container.note_sources:
        blob = _read_slice(handle, source.offset, min(source.size, MAX_SECTION_READ))
        pos = 0
        while pos + 12 <= len(blob):
            namesz = _u32(blob, pos)
            descsz = _u32(blob, pos + 4)
            _ = _u32(blob, pos + 8)
            if namesz > MAX_ELF_NOTE_BYTES or descsz > MAX_ELF_NOTE_BYTES:
                break
            entry_end = pos + 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
            if entry_end > len(blob):
                break
            name_bytes = blob[pos + 12 : pos + 12 + namesz]
            name = name_bytes.rstrip(b"\0").decode("utf-8", errors="replace")
            if name in CARGO_AUDIT_NOTE_OWNERS:
                desc_off = pos + 12 + ((namesz + 3) & ~3)
                return blob[desc_off : desc_off + descsz], f"note:{name}"
            pos = entry_end
    for section in container.sections:
        if section.name == CARGO_AUDIT_SECTION and 0 < section.size <= MAX_SECTION_READ:
            return (
                _read_slice(handle, section.offset, section.size),
                f"section:{section.name}",
            )
    return None


def detect_cargo_auditable(path: str | Path) -> CargoAuditableInfo | None:
    """Read the cargo-auditable crate list. ``None`` when not ELF/markers."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 4)
        if head[:4] != b"\x7fELF":
            return None
        container = _open_container(handle, size)
        if container is None:
            return None
        found = _elf_audit_payload(handle, container)
    if found is None:
        return None
    payload, origin = found
    return _parse_audit_payload(payload, origin)


# ---- Electron fuses ----------------------------------------------------------


def detect_electron_fuses(path: str | Path) -> ElectronFusesInfo | None:
    """Parse the Electron fuse wire. ``None`` when the sentinel is absent."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        off = _chunked_find(handle, size, ELECTRON_FUSE_SENTINEL)
        if off is None:
            return None
        wire_off = off + len(ELECTRON_FUSE_SENTINEL)
        wire_head = _read_slice(handle, wire_off, 2)
        if len(wire_head) < 2:
            raise AnalysisError("truncated Electron fuse wire header")
        schema_version = wire_head[0]
        wire_length = wire_head[1]
        if wire_length == 0 or wire_length > MAX_FUSES:
            raise AnalysisError(f"implausible Electron fuse count {wire_length}")
        wire = _read_slice(handle, wire_off + 2, wire_length)
        if len(wire) < wire_length:
            raise AnalysisError("truncated Electron fuse wire")

    fuses: list[tuple[str, str]] = []
    counts = {"on": 0, "off": 0, "removed": 0, "unknown": 0}
    for idx in range(wire_length):
        if schema_version == 1 and idx < len(ELECTRON_FUSE_NAMES_V1):
            name = ELECTRON_FUSE_NAMES_V1[idx]
        else:
            name = f"fuse_{idx}"
        state = ELECTRON_FUSE_STATES.get(wire[idx], "unknown")
        counts[state] += 1
        fuses.append((name, state))
    evidence = Evidence(
        source="meta.fuses",
        method="fuse-wire-sentinel",
        confidence=Confidence.HIGH,
        detail=f"sentinel at file offset 0x{off:x}, schema v{schema_version}",
        extra={"sentinel_offset": off, "schema_version": schema_version},
    )
    return ElectronFusesInfo(
        fuse_schema_version=schema_version,
        fuse_count=wire_length,
        enabled=counts["on"],
        disabled=counts["off"],
        removed=counts["removed"],
        fuses=tuple(fuses),
        evidence=evidence,
    )


# ---- ELF notes and kernel-module .modinfo ------------------------------------


_GNU_NOTE_TYPES: dict[int, str] = {
    1: "NT_GNU_ABI_TAG",
    2: "NT_GNU_HWCAP",
    3: "NT_GNU_BUILD_ID",
    4: "NT_GNU_PROPERTY_TYPE_0",
    5: "NT_GNU_GOLD_VERSION",
}
_PROCESS_NOTE_TYPES: dict[int, str] = {
    1: "NT_PRSTATUS",
    2: "NT_PRFPREG",
    3: "NT_PRPSINFO",
    4: "NT_PRXREG",
    6: "NT_SIGINFO",
    7: "NT_AUXV",
    0x46494C45: "NT_FILE",
}


def _note_type_name(owner: str, n_type: int) -> str | None:
    """Best-effort symbolic name for an ELF note type."""
    if owner == "GNU":
        return _GNU_NOTE_TYPES.get(n_type)
    if owner in ("CORE", "LINUX", ""):
        return _PROCESS_NOTE_TYPES.get(n_type)
    return None


def _iter_notes(blob: bytes) -> list[tuple[str, int, bytes]]:
    """Bounded (name, type, desc) tuples from one note region."""
    out: list[tuple[str, int, bytes]] = []
    pos = 0
    while pos + 12 <= len(blob) and len(out) < MAX_ELF_NOTES:
        namesz = _u32(blob, pos)
        descsz = _u32(blob, pos + 4)
        n_type = _u32(blob, pos + 8)
        if namesz > MAX_ELF_NOTE_BYTES or descsz > MAX_ELF_NOTE_BYTES:
            break
        entry_end = pos + 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
        if entry_end > len(blob):
            break
        name_bytes = blob[pos + 12 : pos + 12 + namesz]
        desc_off = pos + 12 + ((namesz + 3) & ~3)
        desc = blob[desc_off : desc_off + descsz]
        name = name_bytes.rstrip(b"\0").decode("utf-8", errors="replace")
        out.append((name, n_type, desc))
        pos = entry_end
    return out


def detect_elf_notes(path: str | Path) -> ElfNotesInfo | None:
    """Collect ELF notes from ``PT_NOTE`` segments and note sections."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 4)
        if head[:4] != b"\x7fELF":
            return None
        container = _open_container(handle, size)
        if container is None:
            return None
        notes: list[ElfNote] = []
        build_id: str | None = None
        seg_count = 0
        sect_count = 0
        for source in container.note_sources:
            if source.origin == "PT_NOTE":
                seg_count += 1
            else:
                sect_count += 1
            blob = _read_slice(
                handle, source.offset, min(source.size, MAX_SECTION_READ)
            )
            for name, n_type, desc in _iter_notes(blob):
                if name == "GNU" and n_type == 3:
                    build_id = desc.hex()
                notes.append(
                    ElfNote(
                        name=name,
                        n_type=n_type,
                        n_type_name=_note_type_name(name, n_type),
                        desc_hex=_hex_preview(desc),
                    )
                )
                if len(notes) >= MAX_ELF_NOTES:
                    break
            if len(notes) >= MAX_ELF_NOTES:
                break
    if not notes:
        return None
    evidence = Evidence(
        source="meta.elfnote",
        method="pt-note-and-sht-note",
        confidence=Confidence.HIGH,
        detail=f"{len(notes)} notes from {seg_count} segments, {sect_count} sections",
        extra={"note_segments": seg_count, "note_sections": sect_count},
    )
    return ElfNotesInfo(
        note_count=len(notes),
        note_segments=seg_count,
        note_sections=sect_count,
        build_id=build_id,
        notes=tuple(notes),
        evidence=evidence,
    )


def detect_kernel_module(path: str | Path) -> KernelModuleInfo | None:
    """Read ``.modinfo`` keys from an ``ET_REL`` Linux kernel module."""
    p = Path(path)
    if p.is_dir():
        return None
    _checked_size(p)
    with _open_file(p) as handle:
        ident = _read_slice(handle, 0, 20)
        if len(ident) < 20 or ident[:4] != b"\x7fELF":
            return None
        ei_class, ei_data = ident[4], ident[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            raise AnalysisError("malformed ELF identification bytes")
        wide = ei_class == 2
        endian = "<" if ei_data == 1 else ">"
        head_fmt = endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH")
        need = 48 if wide else 36
        head = _read_slice(handle, 16, need)
        if len(head) < need:
            raise AnalysisError("truncated ELF header")
        fields = struct.unpack(head_fmt, head[:need])
        e_type = int(fields[0])
        if e_type != 1:  # ET_REL only, per the lane contract
            return None
        section = _read_elf_section(
            handle,
            e_shoff=int(fields[5]),
            e_shentsize=int(fields[10]),
            e_shnum=int(fields[11]),
            e_shstrndx=int(fields[12]),
            wide=wide,
            endian=endian,
            wanted=".modinfo",
        )
    if section is None:
        return None
    pairs: dict[str, str] = {}
    for chunk in section[:MAX_SECTION_READ].split(b"\0"):
        if not chunk or len(pairs) >= MAX_MODINFO_KEYS:
            break
        text = chunk.decode("utf-8", errors="replace")
        if "=" not in text:
            continue
        key, value = text.split("=", 1)
        key = key.strip()
        if not key:
            continue
        if len(value) > MAX_MODINFO_VALUE_CHARS:
            value = value[:MAX_MODINFO_VALUE_CHARS] + "..."
        pairs[key] = value
    if not pairs:
        return None
    evidence = Evidence(
        source="meta.modinfo",
        method="et-rel-modinfo-section",
        confidence=Confidence.HIGH,
        detail=f"{len(pairs)} .modinfo keys",
        extra={"keys": sorted(pairs)[:16]},
    )
    return KernelModuleInfo(key_count=len(pairs), modinfo=pairs, evidence=evidence)


def _read_elf_section(
    handle: Any,
    e_shoff: int,
    e_shentsize: int,
    e_shnum: int,
    e_shstrndx: int,
    wide: bool,
    endian: str,
    wanted: str,
) -> bytes | None:
    """Return the raw bytes of one named ELF section (bounded read)."""
    if not (e_shoff and e_shnum and e_shnum <= MAX_ELF_SECTIONS and e_shentsize):
        return None
    strtab = b""
    if 0 < e_shstrndx < e_shnum:
        sh = _read_slice(handle, e_shoff + e_shstrndx * e_shentsize, e_shentsize)
        need = 40 if wide else 24
        if len(sh) >= need:
            sh_fields = struct.unpack(
                endian + ("IIQQQQ" if wide else "IIIIII"), sh[:need]
            )
            sh_off, sh_size = int(sh_fields[4]), int(sh_fields[5])
            if 0 < sh_size <= MAX_SECTION_READ:
                strtab = _read_slice(handle, sh_off, sh_size)
    for idx in range(e_shnum):
        raw = _read_slice(handle, e_shoff + idx * e_shentsize, e_shentsize)
        need = 40 if wide else 24
        if len(raw) < need:
            break
        sh_name, _, _, _, sh_off, sh_size = struct.unpack(
            endian + ("IIQQQQ" if wide else "IIIIII"), raw[:need]
        )
        name = ""
        if strtab and sh_name < len(strtab):
            stop = strtab.find(b"\0", sh_name)
            stop = stop if stop != -1 else len(strtab)
            name = strtab[sh_name:stop].decode("utf-8", errors="replace")
        if name == wanted and 0 < sh_size <= MAX_SECTION_READ:
            return _read_slice(handle, int(sh_off), int(sh_size))
    return None


# ---- desktop app classification ----------------------------------------------


def _pe_has_clr(handle: Any) -> bool:
    """True when a PE has a non-zero CLR header data-directory entry."""
    dos = _read_slice(handle, 0, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return False
    e_lfanew = int(struct.unpack_from("<I", dos, 0x3C)[0])
    coff = _read_slice(handle, e_lfanew, 24)
    if len(coff) < 24 or coff[:4] != b"PE\0\0":
        return False
    opt_size = int(struct.unpack_from("<H", coff, 20)[0])
    opt = _read_slice(handle, e_lfanew + 24, opt_size)
    if len(opt) < 2:
        return False
    magic = int(struct.unpack_from("<H", opt, 0)[0])
    if magic == 0x20B:
        dirs_off, entry = 112, 108
    elif magic == 0x10B:
        dirs_off, entry = 96, 92
    else:
        return False
    if len(opt) < entry + 4:
        return False
    rva_count = _u32(opt, entry)
    if rva_count <= 14 or len(opt) < dirs_off + 15 * 8:
        return False
    return _u32(opt, dirs_off + 14 * 8) != 0


def _walk_tree(root: Path) -> tuple[int, bool, list[tuple[Path, str]]]:
    """Bounded walk returning (files seen, truncated, (file, rel posix path))."""
    seen = 0
    truncated = False
    found: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth >= MAX_DESKTOP_DEPTH:
            dirnames[:] = []
        for name in filenames:
            if seen >= MAX_DESKTOP_FILES:
                return seen, True, found
            seen += 1
            rel = (Path(dirpath).relative_to(root) / name).as_posix()
            found.append((Path(dirpath) / name, rel))
    return seen, truncated, found


def detect_desktop_app(path: str | Path) -> DesktopAppInfo | None:
    """Classify a desktop app directory (Unity/IL2CPP/Unreal/Electron/.NET)."""
    p = Path(path)
    if not p.is_dir():
        return None
    seen, truncated, files = _walk_tree(p)
    if not files:
        return None
    key_files: list[str] = []
    flags: dict[str, bool] = {
        "unity": False,
        "il2cpp": False,
        "unreal": False,
        "electron": False,
        "dotnet": False,
    }
    pe_probes: list[Path] = []

    def _mark(flag: str, rel: str) -> None:
        flags[flag] = True
        if len(key_files) < MAX_DESKTOP_KEY_FILES and rel not in key_files:
            key_files.append(rel)

    for file_path, rel in files:
        lower = file_path.name.lower()
        parent = file_path.parent
        if lower == "gameassembly.dll" or lower == "libil2cpp.so":
            _mark("il2cpp", rel)
        elif lower == "global-metadata.dat":
            _mark("il2cpp", rel)
        elif lower == "globalgamemanagers" or lower == "unity default resources":
            _mark("unity", rel)
        elif lower == "app.asar":
            _mark("electron", rel)
        elif lower.endswith(".pak"):
            _mark("unreal", rel)
        elif lower.endswith((".exe", ".dll")) and len(pe_probes) < MAX_DESKTOP_PE_PROBES:
            pe_probes.append(file_path)
        if parent.name.endswith("_Data"):
            _mark("unity", rel)
    for probe in pe_probes:
        try:
            with _open_file(probe) as handle:
                if _pe_has_clr(handle):
                    _mark("dotnet", probe.relative_to(p).as_posix())
                    break
        except (AnalysisError, OSError):
            continue

    frameworks = tuple(name for name, hit in flags.items() if hit)
    if flags["unity"] and flags["il2cpp"]:
        classification = "unity-il2cpp"
    elif flags["unity"]:
        classification = "unity"
    elif flags["unreal"]:
        classification = "unreal"
    elif flags["electron"]:
        classification = "electron"
    elif flags["dotnet"]:
        classification = "dotnet"
    else:
        return None
    evidence = Evidence(
        source="meta.desktop",
        method="bounded-directory-walk",
        confidence=Confidence.HIGH,
        detail=(
            f"classified {classification}; {seen} files scanned"
            + (" (cap reached)" if truncated else "")
        ),
        extra={"frameworks": list(frameworks), "scan_truncated": truncated},
    )
    return DesktopAppInfo(
        classification=classification,
        frameworks=frameworks,
        key_files=tuple(key_files[:MAX_DESKTOP_KEY_FILES]),
        files_scanned=seen,
        scan_truncated=truncated,
        evidence=evidence,
    )


# ---- Erlang BEAM (IFF container) ---------------------------------------------


def _beam_parse_compile_info(data: bytes, warnings: list[str]) -> tuple[tuple[str, ...], bool]:
    """Decode the deprecated ``c`` chunk: atom-count + (u16 length, name) rows.

    The old compile-info chunk stores its atoms in the same shape as the
    ``Atom`` chunk (a big-endian count followed by length-prefixed names).
    Anything that does not conform is reported as ``decoded=False`` with a
    warning rather than a hard error -- the chunk is optional and deprecated.
    """
    if len(data) < 4:
        return (), False
    count = int(struct.unpack_from(">I", data, 0)[0])
    cursor = 4
    atoms: list[str] = []
    for _ in range(min(count, MAX_BEAM_ATOMS)):
        if cursor + 2 > len(data):
            _note(warnings, "compile-info chunk truncated mid-atom")
            return tuple(atoms), False
        length = struct.unpack_from(">H", data, cursor)[0]
        cursor += 2
        if cursor + length > len(data):
            _note(warnings, "compile-info atom overruns its chunk")
            return tuple(atoms), False
        raw = data[cursor : cursor + length]
        cursor += length
        if not raw or not all(0x20 <= byte < 0x7F for byte in raw):
            _note(warnings, "compile-info atom is not printable ASCII")
            return tuple(atoms), False
        atoms.append(raw.decode("ascii"))
    if count > MAX_BEAM_ATOMS:
        _note(warnings, f"compile-info atom limit {MAX_BEAM_ATOMS} reached; further atoms dropped")
    return tuple(atoms), True


def detect_beam(path: str | Path) -> BeamInfo | None:
    """Inspect an Erlang BEAM file (``FOR1`` + ``BEAM`` IFF). ``None`` when not BEAM."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 12)
        if len(head) < 12:
            return None
        if head[:4] != b"FOR1" or head[8:12] != b"BEAM":
            return None
        iff_size = int(struct.unpack_from(">I", head, 4)[0])
        if iff_size < 4:
            raise AnalysisError(f"BEAM IFF size {iff_size} is below the 'BEAM' form type")
        end = min(size, 8 + iff_size)
        cursor = 12
        chunks: list[tuple[str, int]] = []
        warnings: list[str] = []
        truncated = False
        compile_atoms: tuple[str, ...] = ()
        compile_decoded = False
        while cursor + 8 <= size and cursor < end:
            if len(chunks) >= MAX_BEAM_CHUNKS:
                truncated = True
                _note(warnings, f"chunk limit {MAX_BEAM_CHUNKS} reached; further chunks dropped")
                break
            block = _read_slice(handle, cursor, 8)
            if len(block) < 8:
                break
            name = block[:4]
            length = int(struct.unpack_from(">I", block, 4)[0])
            # Short chunk names are NUL-padded to four bytes ("c", 0, 0, 0).
            label_raw = name.rstrip(b"\x00")
            if not label_raw or not all(0x20 <= byte < 0x7F for byte in label_raw):
                raise AnalysisError(
                    f"BEAM chunk name {name.hex()} at offset {cursor} is not printable ASCII"
                )
            if cursor + 8 + length > end:
                raise AnalysisError(
                    f"BEAM chunk {label_raw.decode('ascii')!r} at offset {cursor} declares "
                    f"{length} bytes, overrunning the IFF form (size {iff_size})"
                )
            label = label_raw.decode("ascii")
            chunks.append((label, length))
            if label == "c" and length > 0:
                compile_atoms, compile_decoded = _beam_parse_compile_info(
                    _read_slice(handle, cursor + 8, min(length, MAX_SECTION_READ)), warnings
                )
            cursor += 8 + length + (length & 1)
        if not chunks:
            raise AnalysisError("BEAM file carries no chunk table")
        evidence = Evidence(
            source="meta.beam",
            method="iff-chunk-table",
            confidence=Confidence.HIGH,
            detail=_join_notes(f"{len(chunks)} chunks; form size {iff_size}", warnings),
            extra={"chunks": ",".join(name for name, _ in chunks[:8])},
        )
        return BeamInfo(
            iff_size=iff_size,
            chunk_count=len(chunks),
            chunks=tuple(chunks),
            chunks_truncated=truncated,
            compile_info_atoms=compile_atoms,
            compile_info_decoded=compile_decoded,
            evidence=evidence,
        )


# ---- Unity IL2CPP global metadata --------------------------------------------


def _il2cpp_plausible(offset: int, length: int, size: int) -> bool:
    """One header (offset, size) pair is plausible when it lands inside the file.

    Offset 0 is never valid -- the file opens with the header itself -- so
    zero-padded header tails stop the walk instead of being counted as empty
    tables.
    """
    return 0 < offset < size and 0 <= length and offset + length <= size


def detect_il2cpp(path: str | Path) -> Il2CppInfo | None:
    """Inspect Unity IL2CPP ``global-metadata.dat``. ``None`` when not IL2CPP.

    The header opens with the ``0xFAB11BAF`` sanity word and a version int at
    offset 4 (families 24/27/29/31/39 are known), then a table of
    ``(offset, size)`` int pairs. Byte order follows whichever encoding the
    magic arrived in (little-endian in every file Unity ships; big-endian is
    accepted for the mirrored variant). Counts derive from the documented
    record strides; the type count is a floor because the exact
    type-definition stride varies inside one family, and the parameter count
    follows the documented v24.1+ family layout.
    """
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 16)
    if len(head) < 8:
        return None
    le_magic = struct.unpack_from("<I", head, 0)[0]
    be_magic = struct.unpack_from(">I", head, 0)[0]
    if le_magic == IL2CPP_MAGIC:
        endian = "little"
    elif be_magic == IL2CPP_MAGIC:
        endian = "big"
    else:
        return None
    fmt = "<" if endian == "little" else ">"
    version = int(struct.unpack_from(f"{fmt}i", head, 4)[0])
    if version <= 0 or version > 1000:
        raise AnalysisError(f"implausible IL2CPP version {version}")
    known = version in IL2CPP_KNOWN_VERSIONS
    with _open_file(p) as handle:
        window = _read_slice(handle, 8, MAX_IL2CPP_TABLES * 8)
    warnings: list[str] = []
    pairs: list[tuple[int, int, int]] = []
    tables_truncated = False
    for index in range(len(window) // 8):
        offset, length = struct.unpack_from(f"{fmt}ii", window, index * 8)
        if not _il2cpp_plausible(offset, length, size):
            _note(warnings, f"header pair {index} is not plausible; stopping the table walk")
            break
        pairs.append((index, offset, length))
        if len(pairs) >= MAX_IL2CPP_TABLES:
            tables_truncated = True
            _note(warnings, f"table limit {MAX_IL2CPP_TABLES} reached; further pairs dropped")
            break
    if not pairs:
        raise AnalysisError("IL2CPP header carries no plausible table pairs")
    by_name = {
        name: pairs[position]
        for name, position in IL2CPP_TABLE_POSITIONS.items()
        if position < len(pairs)
    }
    string_literals = by_name.get("string_literals")
    string_blob = by_name.get("string_blob")
    events = by_name.get("events")
    properties = by_name.get("properties")
    methods = by_name.get("methods")
    params = by_name.get("parameters")
    fields = by_name.get("fields")
    types = by_name.get("type_definitions")
    string_count = string_literals[2] // IL2CPP_STRING_LITERAL_STRIDE if string_literals else None
    event_count = events[2] // IL2CPP_EVENT_STRIDE if events else None
    property_count = (
        properties[2] // (5 * 4) if properties and properties[2] % (5 * 4) == 0 else None
    )
    param_count = (
        params[2] // IL2CPP_PARAM_STRIDE
        if params and params[2] % IL2CPP_PARAM_STRIDE == 0
        else None
    )
    field_count = fields[2] // IL2CPP_FIELD_STRIDE if fields else None
    type_count_min = types[2] // IL2CPP_TYPE_STRIDE_FLOOR if types else None
    if not known:
        _note(
            warnings,
            f"metadata version {version} is outside the known families "
            f"{', '.join(str(item) for item in IL2CPP_KNOWN_VERSIONS)}; the v24.1+ layout "
            "is applied structurally",
        )
    if param_count is None and "parameters" in by_name:
        _note(warnings, "parameters table size is not a whole number of 12-byte records")
    evidence = Evidence(
        source="meta.il2cpp",
        method="global-metadata-header",
        confidence=Confidence.HIGH,
        detail=_join_notes(
            (
                f"version {version} ({'known' if known else 'unknown'} family, {endian}-endian); "
                f"{len(pairs)} header pairs"
            ),
            warnings,
        ),
        extra={"version": version},
    )
    return Il2CppInfo(
        version=version,
        known_version=known,
        endian=endian,
        string_count=string_count,
        string_table_bytes=string_blob[2] if string_blob else None,
        event_count=event_count,
        property_count=property_count,
        method_table_bytes=methods[2] if methods else None,
        param_count=param_count,
        field_count=field_count,
        type_count_min=type_count_min,
        table_pairs=tuple(pairs),
        tables_truncated=tables_truncated,
        evidence=evidence,
    )


# ---- Flutter / Dart AOT snapshots ---------------------------------------------


def _scan_all_magics(
    handle: Any, size: int, needle: bytes, cap: int
) -> tuple[tuple[int, ...], bool]:
    """Bounded chunked scan for *every* occurrence of ``needle`` (up to ``cap``)."""
    hits: list[int] = []
    overlap = len(needle) - 1
    cursor = 0
    truncated = False
    while cursor < size:
        window = _read_slice(handle, cursor, min(READ_CHUNK, size - cursor))
        if not window:
            break
        start = 0
        while True:
            idx = window.find(needle, start)
            if idx == -1:
                break
            hits.append(cursor + idx)
            start = idx + 1
            if len(hits) >= cap:
                truncated = True
                break
        if truncated:
            break
        if cursor + len(window) >= size:
            break
        cursor = cursor + len(window) - overlap
    return tuple(hits), truncated


def detect_flutter(path: str | Path) -> FlutterSnapshotInfo | None:
    """Detect Flutter/Dart AOT snapshot magics inside a ``.so`` or blob."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        vm_hits, vm_trunc = _scan_all_magics(handle, size, FLUTTER_VM_MAGIC, MAX_FLUTTER_OFFSETS)
        isolate_hits, iso_trunc = _scan_all_magics(
            handle, size, FLUTTER_ISOLATE_MAGIC, MAX_FLUTTER_OFFSETS
        )
    if not vm_hits and not isolate_hits:
        return None
    kinds: list[str] = []
    if vm_hits:
        kinds.append("vm")
    if isolate_hits:
        kinds.append("isolate")
    warnings: list[str] = []
    if vm_trunc or iso_trunc:
        _note(
            warnings,
            f"snapshot magic limit {MAX_FLUTTER_OFFSETS} per kind reached; further hits dropped",
        )
    evidence = Evidence(
        source="meta.flutter",
        method="snapshot-magic-scan",
        confidence=Confidence.HIGH,
        detail=_join_notes(f"snapshot kinds: {', '.join(kinds)}", warnings),
        extra={"vm_hits": len(vm_hits), "isolate_hits": len(isolate_hits)},
    )
    return FlutterSnapshotInfo(
        kinds=tuple(kinds),
        vm_offsets=vm_hits,
        isolate_offsets=isolate_hits,
        scan_truncated=vm_trunc or iso_trunc,
        evidence=evidence,
    )


# ---- HarmonyOS HAP ------------------------------------------------------------


def detect_hap(path: str | Path) -> HapInfo | None:
    """Inspect a HarmonyOS HAP (a zip carrying ``pack.info``). ``None`` when not HAP.

    Only the structure is reported: the central-directory entry count, a
    bounded slice of entry names, and the ``pack.info`` descriptor decoded as
    JSON when it parses (module count plus a bounded summary string). A file
    that starts as a zip but refuses to open raises the typed malformed-zip
    error; a valid zip without ``pack.info`` (an APK, a jar) is simply not a HAP.
    """
    p = Path(path)
    if p.is_dir():
        return None
    _checked_size(p)
    with _open_file(p) as handle:
        lead = _read_slice(handle, 0, 4)
    if lead != b"PK\x03\x04":
        return None
    try:
        with zipfile.ZipFile(p) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            pack = archive.read(HAP_PACK_INFO) if HAP_PACK_INFO in names else None
    except zipfile.BadZipFile as exc:
        raise AnalysisError(f"malformed zip archive (HAP): {p}: {exc}") from exc
    except OSError as exc:
        raise AnalysisError(f"cannot read {p}: {exc}") from exc
    if pack is None:
        return None
    warnings: list[str] = []
    module_count: int | None = None
    summary_text: str | None = None
    decoded = False
    try:
        document = json.loads(pack.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _note(warnings, "pack.info is not decodable as UTF-8 JSON; reported as raw bytes")
        document = None
    if isinstance(document, dict):
        decoded = True
        summary_text = json.dumps(document, ensure_ascii=False, sort_keys=True)[:MAX_HAP_INFO_CHARS]
        modules = document.get("summary", {}).get("modules")
        if isinstance(modules, list):
            module_count = len(modules)
        else:
            _note(warnings, "pack.info has no summary.modules list; module count unknown")
    else:
        summary_text = pack[:MAX_HAP_INFO_CHARS].decode("utf-8", errors="replace")
    if len(names) > MAX_HAP_ENTRIES:
        _note(warnings, f"entry-name limit {MAX_HAP_ENTRIES} reached; further names dropped")
    evidence = Evidence(
        source="meta.hap",
        method="zip-pack-info",
        confidence=Confidence.HIGH,
        detail=_join_notes(
            (
                f"{len(infos)} entries; pack.info "
                + ("decoded" if decoded else "not decoded")
                + (f"; {module_count} modules" if module_count is not None else "")
            ),
            warnings,
        ),
        extra={"entries": len(infos)},
    )
    return HapInfo(
        entry_count=len(infos),
        entry_names=tuple(names[:MAX_HAP_ENTRIES]),
        entries_truncated=len(names) > MAX_HAP_ENTRIES,
        module_count=module_count,
        pack_info_summary=summary_text,
        pack_info_decoded=decoded,
        evidence=evidence,
    )


# ---- CUDA fatbin ---------------------------------------------------------------


def detect_cuda_fatbin(path: str | Path) -> CudaFatbinInfo | None:
    """Inspect a CUDA fatbin container (magic ``0xBA55ED50``). ``None`` when not fatbin."""
    p = Path(path)
    if p.is_dir():
        return None
    size = _checked_size(p)
    with _open_file(p) as handle:
        head = _read_slice(handle, 0, 16)
        if len(head) < 4 or struct.unpack_from("<I", head, 0)[0] != CUDA_FATBIN_MAGIC:
            return None
        if len(head) < 16:
            raise AnalysisError("truncated fatbin header (need 16 bytes)")
        version = int(struct.unpack_from("<H", head, 4)[0])
        header_size = int(struct.unpack_from("<H", head, 6)[0])
        data_size = int(struct.unpack_from("<Q", head, 8)[0])
        if header_size < 16:
            raise AnalysisError(f"fatbin header size {header_size} is below the 16-byte minimum")
        limit = min(size, header_size + data_size) if data_size else size
        cursor = header_size
        warnings: list[str] = []
        kinds: list[str] = []
        elf_count = 0
        ptx_count = 0
        truncated = False
        while cursor + 16 <= size and cursor < limit:
            if len(kinds) >= MAX_CUDA_ENTRIES:
                truncated = True
                _note(warnings, f"entry limit {MAX_CUDA_ENTRIES} reached; further entries dropped")
                break
            block = _read_slice(handle, cursor, 16)
            kind = int(struct.unpack_from("<H", block, 0)[0])
            entry_version = int(struct.unpack_from("<H", block, 2)[0])
            entry_header = int(struct.unpack_from("<I", block, 4)[0])
            entry_size = int(struct.unpack_from("<Q", block, 8)[0])
            if entry_header < 16:
                raise AnalysisError(
                    f"fatbin entry at offset {cursor} declares header size {entry_header}"
                )
            if cursor + entry_header + entry_size > size:
                raise AnalysisError(
                    f"fatbin entry at offset {cursor} ({entry_header}+{entry_size} bytes) "
                    "overruns the container"
                )
            label = CUDA_ENTRY_KINDS.get(kind, f"kind-{kind}")
            kinds.append(label)
            if kind == 1:
                elf_count += 1
            elif kind == 2:
                ptx_count += 1
            if entry_version == 0:
                _note(warnings, f"fatbin entry at offset {cursor} reports version 0")
            cursor += entry_header + entry_size
    if not kinds and data_size:
        raise AnalysisError("fatbin declares a payload but carries no entries")
    evidence = Evidence(
        source="meta.cuda",
        method="fatbin-header",
        confidence=Confidence.HIGH,
        detail=_join_notes(
            f"version {version}; {len(kinds)} entries ({elf_count} elf, {ptx_count} ptx)",
            warnings,
        ),
        extra={"version": version},
    )
    return CudaFatbinInfo(
        version=version,
        header_size=header_size,
        data_size=data_size,
        entry_count=len(kinds),
        elf_count=elf_count,
        ptx_count=ptx_count,
        kinds=tuple(kinds),
        entries_truncated=truncated,
        evidence=evidence,
    )


# ---- auto-detecting entry point ----------------------------------------------

_KIND_PRIORITY: tuple[tuple[str, str], ...] = (
    ("apk", "apk-signing"),
    ("hap", "harmonyos-hap"),
    ("pyc", "python-pyc"),
    ("beam", "erlang-beam"),
    ("il2cpp", "il2cpp-metadata"),
    ("flutter", "flutter-dart-aot"),
    ("cuda", "cuda-fatbin"),
    ("go", "go-buildinfo"),
    ("cargo-auditable", "cargo-auditable"),
    ("electron-fuses", "electron-fuses"),
    ("kernel-module", "kernel-module"),
    ("elf-notes", "elf-notes"),
)


def inspect_metadata(path: str | Path) -> MetadataReport:
    """Auto-detect the format at ``path`` and return one metadata report.

    Directories are classified as desktop app layouts; files run through
    every typed detector (``None`` = format does not match). Unknown or
    malformed inputs raise :class:`AnalysisError`.
    """
    p = Path(path)
    if not p.exists():
        raise AnalysisError(f"path does not exist: {p}")
    if p.is_dir():
        info = detect_desktop_app(p)
        if info is None:
            raise AnalysisError(f"no supported desktop-app layout detected in {p}")
        return MetadataReport(
            path=str(p),
            kind="desktop",
            details={"desktop": info.to_dict()},
            evidence=(info.evidence,),
        )
    size = _checked_size(p)
    results: dict[str, Any] = {}
    evidence: list[Evidence] = []
    apk = detect_apk_signing(p)
    if apk is not None:
        results["apk"] = apk.to_dict()
        evidence.extend(apk.evidence)
    hap = detect_hap(p)
    if hap is not None:
        results["hap"] = hap.to_dict()
        evidence.append(hap.evidence)
    pyc = detect_pyc(p)
    if pyc is not None:
        results["pyc"] = pyc.to_dict()
        evidence.append(pyc.evidence)
    beam = detect_beam(p)
    if beam is not None:
        results["beam"] = beam.to_dict()
        evidence.append(beam.evidence)
    il2cpp = detect_il2cpp(p)
    if il2cpp is not None:
        results["il2cpp"] = il2cpp.to_dict()
        evidence.append(il2cpp.evidence)
    flutter = detect_flutter(p)
    if flutter is not None:
        results["flutter"] = flutter.to_dict()
        evidence.append(flutter.evidence)
    cuda = detect_cuda_fatbin(p)
    if cuda is not None:
        results["cuda"] = cuda.to_dict()
        evidence.append(cuda.evidence)
    go = detect_go_buildinfo(p)
    if go is not None:
        results["go"] = go.to_dict()
        evidence.append(go.evidence)
    cargo = detect_cargo_auditable(p)
    if cargo is not None:
        results["cargo-auditable"] = cargo.to_dict()
        evidence.append(cargo.evidence)
    fuses = detect_electron_fuses(p)
    if fuses is not None:
        results["electron-fuses"] = fuses.to_dict()
        evidence.append(fuses.evidence)
    kmod = detect_kernel_module(p)
    if kmod is not None:
        results["kernel-module"] = kmod.to_dict()
        evidence.append(kmod.evidence)
    notes = detect_elf_notes(p)
    if notes is not None:
        results["elf-notes"] = notes.to_dict()
        evidence.append(notes.evidence)
    if not results:
        raise AnalysisError(f"unrecognized file format: {p} ({size} bytes)")
    kind = next(report_kind for key, report_kind in _KIND_PRIORITY if key in results)
    return MetadataReport(
        path=str(p), kind=kind, details=results, evidence=tuple(evidence)
    )








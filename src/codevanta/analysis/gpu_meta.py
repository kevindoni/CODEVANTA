"""GPU code-object inspector: CUDA fatbin (deep), CUBIN, and COB bundles.

Complements the shallow ``binmeta.detect_cuda_fatbin`` summary with the detail
REA-style tooling provides: per-entry kinds, embedded ``sm_XX`` architecture
detection, PTX text previews, and CUBIN section listings. Structure only:
nothing is compiled, decompiled, or verified for trust.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 16
MAX_SECTIONS = 32
MAX_ARCHS = 8

FATBIN_MAGIC = 0xBA55ED50
CUDA_ENTRY_KINDS = {0: "unknown", 1: "elf", 2: "ptx"}

__all__ = ["GpuEntry", "GpuCodeSummary", "inspect_gpu"]

ELF_MAGIC = bytes([0x7F]) + b"ELF"
ELF64_CLASS = bytes([2])
NUL = bytes([0])
PTX_TEXT_MARKERS = (b";%PTX", b".visible .entry")
COB_MAGIC = bytes([0x43, 0x4F, 0x42, 0x01])



class GpuEntry:
    """One code entry inside a GPU container."""

    __slots__ = ("kind", "offset", "size", "arch", "is_ptx_text")

    def __init__(self, kind: str, offset: int, size: int, arch: str | None, is_ptx_text: bool) -> None:
        self.kind = kind
        self.offset = offset
        self.size = size
        self.arch = arch
        self.is_ptx_text = is_ptx_text

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "size": self.size,
            "arch": self.arch,
            "is_ptx_text": self.is_ptx_text,
        }


class GpuCodeSummary:
    """The typed GPU container summary."""

    __slots__ = ("kind", "arch", "file_size", "entries", "warnings", "evidence")

    def __init__(
        self,
        kind: str,
        file_size: int,
        entries: tuple[GpuEntry, ...],
        warnings: tuple[str, ...],
        evidence: Evidence,
    ) -> None:
        self.kind = kind
        self.file_size = file_size
        self.entries = entries
        self.warnings = warnings
        self.evidence = evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "file_size": self.file_size,
            "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _find_arch(payload: bytes) -> str | None:
    idx = payload.find(b"sm_")
    if idx == -1:
        return None
    window = payload[idx : idx + 16]
    raw_token = window.split()[0] if window.split() else b""
    strip_chars = bytes([0x29, 0x00, 0x2C, 0x3B, 0x5B, 0x5D])
    raw_token = raw_token.rstrip(strip_chars)
    token = raw_token.decode("ascii", "replace")
    return token or None


def _parse_fatbin(data: bytes) -> GpuCodeSummary:
    warnings: list[str] = []
    if len(data) < 16:
        raise AnalysisError("truncated fatbin header (need 16 bytes)")
    version = int(struct.unpack_from("<H", data, 4)[0])
    header_size = int(struct.unpack_from("<H", data, 6)[0])
    data_size = int(struct.unpack_from("<Q", data, 8)[0])
    if header_size < 16:
        raise AnalysisError(f"fatbin header size {header_size} is below the 16-byte minimum")
    limit = min(len(data), header_size + data_size) if data_size else len(data)
    entries: list[GpuEntry] = []
    archs: list[str] = []
    cursor = header_size
    while cursor + 16 <= limit and len(entries) < MAX_ENTRIES:
        kind_raw = int(struct.unpack_from("<H", data, cursor)[0])
        entry_version = int(struct.unpack_from("<H", data, cursor + 2)[0])
        entry_header = int(struct.unpack_from("<I", data, cursor + 4)[0])
        entry_size = int(struct.unpack_from("<Q", data, cursor + 8)[0])
        if entry_header < 16:
            raise AnalysisError(f"fatbin entry at {cursor} declares header size {entry_header}")
        if cursor + entry_header + entry_size > limit:
            raise AnalysisError(f"fatbin entry at {cursor} overruns the container")
        payload = data[cursor + entry_header : cursor + entry_header + entry_size]
        kind = CUDA_ENTRY_KINDS.get(kind_raw, f"kind-{kind_raw}")
        arch = _find_arch(payload[:512])
        if arch and arch not in archs and len(archs) < MAX_ARCHS:
            archs.append(arch)
        is_ptx = kind_raw == 2 or payload.lstrip().startswith(b"//")
        entries.append(GpuEntry(kind, cursor, entry_size, arch, is_ptx))
        if entry_version == 0:
            warnings.append(f"entry at {cursor} reports version 0")
        cursor += entry_header + entry_size
    else:
        if cursor < limit and len(entries) >= MAX_ENTRIES:
            warnings.append(f"entry limit {MAX_ENTRIES} reached; further entries dropped")
    detail = f"cuda fatbin v{version}; {len(entries)} entries; archs={archs or 'none detected'}"
    if warnings:
        detail += "; " + "; ".join(warnings[:8])
    evidence = Evidence(
        source="gpu.cuda",
        method="fatbin-walk",
        confidence=Confidence.MEDIUM,
        detail=detail,
        extra={"version": version, "archs": list(archs)},
    )
    return GpuCodeSummary("cuda-fatbin", len(data), tuple(entries), tuple(warnings), evidence)


def _parse_cubin(data: bytes) -> GpuCodeSummary:
    warnings: list[str] = []
    if len(data) < 64:
        raise AnalysisError("truncated cubin (need at least 64 bytes for the ELF header)")
    if data[:4] != ELF_MAGIC:
        raise AnalysisError("not an ELF image (cubin expected 0x7fELF)")
    if data[4:5] != ELF64_CLASS:
        raise AnalysisError("only ELF64 cubins are parsed; this is not ELF64")
    shoff = int(struct.unpack_from("<Q", data, 40)[0])
    shentsize = int(struct.unpack_from("<H", data, 58)[0])
    shnum = int(struct.unpack_from("<H", data, 60)[0])
    shstrndx = int(struct.unpack_from("<H", data, 62)[0])
    if shentsize == 0:
        raise AnalysisError("cubin declares a zero-sized section header entry")
    if shoff + shentsize * max(shnum, 1) > len(data):
        raise AnalysisError("cubin section header table overruns the file")
    sections: list[GpuEntry] = []
    strtab = b""
    if 0 <= shstrndx < shnum:
        base = shoff + shstrndx * shentsize
        str_off = int(struct.unpack_from("<Q", data, base + 24)[0])
        str_size = int(struct.unpack_from("<Q", data, base + 32)[0])
        if str_off + str_size <= len(data):
            strtab = data[str_off : str_off + str_size]
    for i in range(min(shnum, MAX_SECTIONS)):
        base = shoff + i * shentsize
        name_idx = int(struct.unpack_from("<I", data, base)[0])
        offset = int(struct.unpack_from("<Q", data, base + 24)[0])
        s_size = int(struct.unpack_from("<Q", data, base + 32)[0])
        if strtab:
            name = strtab[name_idx:].split(NUL)[0].decode("ascii", "replace")
        else:
            name = f"section-{i}"
        sections.append(GpuEntry(name, offset, s_size, None, False))
    has_ptx = any(marker in data for marker in PTX_TEXT_MARKERS)
    if not has_ptx:
        warnings.append("no PTX text marker found in this cubin")
    detail = f"cubin; {len(sections)} sections; ptx_marker={has_ptx}"
    evidence = Evidence(
        source="gpu.cuda",
        method="elf-section-walk",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"sections": len(sections)},
    )
    return GpuCodeSummary("cubin", len(data), tuple(sections), tuple(warnings), evidence)


def _parse_cob(data: bytes) -> GpuCodeSummary:
    lines = data[:2048].decode("ascii", "replace").splitlines()[:8]
    archs = [entry.strip() for entry in lines if entry.strip().startswith(("host:", "device:"))]
    if not archs:
        raise AnalysisError("COB bundle header carries no host/device lines")
    detail = f"clang-offload-bundle; {len(archs)} host/device lines"
    evidence = Evidence(
        source="gpu.cuda",
        method="cob-text-header",
        confidence=Confidence.MEDIUM,
        detail=detail,
        extra={"lines": len(archs)},
    )
    entries = tuple(
        GpuEntry(
            entry.split(":")[0].strip(),
            0,
            0,
            entry.split(":")[1].strip() if ":" in entry else None,
            False,
        )
        for entry in archs
    )
    return GpuCodeSummary("cob", len(data), entries, (), evidence)


def inspect_gpu_data(data: bytes) -> GpuCodeSummary:
    """Auto-detect and deeply inspect a GPU container from raw bytes."""
    if len(data) > MAX_FILE_BYTES:
        raise AnalysisError(f"file exceeds the {MAX_FILE_BYTES} byte limit: {len(data)}")
    if len(data) >= 4 and int(struct.unpack_from('<I', data, 0)[0]) == FATBIN_MAGIC:
        return _parse_fatbin(data)
    if data[:4] == ELF_MAGIC and (b'NV' in data[:2048] or b'.nv.info' in data[:4096]):
        return _parse_cubin(data)
    if data[:4] == COB_MAGIC or data.startswith(b'Version:') or b'device:' in data[:512]:
        return _parse_cob(data)
    raise AnalysisError(f'unrecognized GPU container format ({len(data)} bytes)')


def inspect_gpu(path: str | Path) -> GpuCodeSummary:
    """Auto-detect and deeply inspect a GPU container at ``path``."""
    p = Path(path)
    if not p.is_file():
        raise AnalysisError(f"path is not a regular file: {p}")
    return inspect_gpu_data(p.read_bytes())

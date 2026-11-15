"""Pure-Python PE delay-load import decoder (lane-dload).

Reads the ``IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`` directory (index 13) of a
PE32/PE32+ image and returns a typed :class:`DelayLoadSummary`:

* one bounded record per ``ImgDelayDescr``: DLL name, raw ``grAttrs`` with
  the named trait bits, the layout version (``v1`` 32-bit fields or ``v2``
  64-bit fields, chosen by the directory size) and the IAT/INT RVAs;
* the delay imports themselves: each import-name-table entry is an
  ``IMAGE_IMPORT_BY_NAME`` (hint WORD + NUL-terminated name) or an ordinal,
  walked until the NULL terminator (bounded 32 DLLs x 512 imports x 128
  name chars, every bound reported honestly).

Descriptor traits: when ``grAttrs`` bit 0 (``dlattrRva``) is set every
pointer field is an RVA; otherwise the fields hold bind-time addresses,
which this parser approximates as RVAs and warns about. A PE without a
delay-load directory is normal and yields a summary with
``delay_load_present=False``; a truncated descriptor array, an unmapped
DLL-name/INT/name RVA raise the typed
:class:`~codevanta.core.report.AnalysisError`. Parse-only: nothing here
resolves the imports, it reports what the tables declare.
"""

from __future__ import annotations

import dataclasses
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DLATTR_CF_CHECK",
    "DLATTR_RVA",
    "EVIDENCE_SOURCE",
    "MAX_DLLS",
    "MAX_IMPORTS_PER_DLL",
    "MAX_NAME_CHARS",
    "DelayLoadSummary",
    "GR_ATTR_NAMES",
    "inspect_delay_loads",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "pe.delayload"

#: Data-directory index of the delay-load import table (winnt.h).
DIRECTORY_INDEX = 13

#: Descriptors walked per summary (bounded work).
MAX_DLLS = 32

#: Import names kept per descriptor (bounded output).
MAX_IMPORTS_PER_DLL = 512

#: Characters kept in one DLL or import name (bounded output).
MAX_NAME_CHARS = 128

#: ``ImgDelayDescr`` v1 stride in bytes (delayimp.h).
V1_SIZE = 32

#: ``ImgDelayDescr`` v2 stride in bytes (64-bit fields, CFG-checked IAT).
V2_SIZE = 64

#: ``grAttrs`` bit 0: the descriptor's pointer fields are RVAs (dlattrRva).
DLATTR_RVA = 0x1

#: ``grAttrs`` bit 1: reserved/unused slot (dlattrUnused).
DLATTR_UNUSED = 0x2

#: ``grAttrs`` bit 2: conservative static binding (dlattrConservative).
DLATTR_CONSERVATIVE = 0x4

#: ``grAttrs`` bit 3: CFG check bit on the delay-load IAT (v2 descriptors).
DLATTR_CF_CHECK = 0x8

#: Known ``grAttrs`` bits with their trait names; unknown bits warn.
GR_ATTR_NAMES: dict[int, str] = {
    DLATTR_RVA: "rva",
    DLATTR_UNUSED: "unused",
    DLATTR_CONSERVATIVE: "conservative",
    DLATTR_CF_CHECK: "cf-check",
}

#: Union of the named ``grAttrs`` bits.
KNOWN_ATTR_MASK = sum(GR_ATTR_NAMES)


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class DelayLoadSummary:
    """Deep view of one PE's delay-load imports. Parse-only, bounded."""

    path: str
    delay_load_present: bool
    descriptor_count: int
    descriptors: tuple[dict[str, Any], ...]
    descriptors_truncated: bool
    import_count: int
    import_total: int
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "delay_load_present": self.delay_load_present,
            "descriptor_count": self.descriptor_count,
            "descriptors": [dict(descriptor) for descriptor in self.descriptors],
            "descriptors_truncated": self.descriptors_truncated,
            "import_count": self.import_count,
            "import_total": self.import_total,
            "warnings": list(self.warnings),
        }


# ---- PE header walking -------------------------------------------------------


@dataclass(frozen=True)
class _PeImage:
    """The few PE header facts the delay-load parser needs (validated)."""

    directories: tuple[tuple[int, int], ...]  # (rva, size) per index
    sections: tuple[tuple[int, int, int, int], ...]  # (va, vsize, off, rawsize)


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def _parse_pe_image(data: bytes) -> _PeImage:
    """Validate the DOS/PE/COFF/optional headers and snapshot the facts."""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise AnalysisError("missing MZ magic")
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature not found at e_lfanew")
    num_sections = _u16(data, e_lfanew + 6)
    opt_off = e_lfanew + 24
    opt_magic = _u16(data, opt_off)
    if opt_magic not in (0x10B, 0x20B):
        raise AnalysisError(f"unsupported optional header magic 0x{opt_magic:x}")
    opt_size = _u16(data, e_lfanew + 20)
    num_dirs_off = opt_off + (92 if opt_magic == 0x10B else 108)
    dd_off = opt_off + (96 if opt_magic == 0x10B else 112)
    if num_dirs_off + 4 > len(data):
        raise AnalysisError("truncated before the data-directory count")
    num_dirs = _u32(data, num_dirs_off)
    if num_dirs > 16:
        raise AnalysisError(f"unreasonable data-directory count {num_dirs}")
    directories: list[tuple[int, int]] = []
    for index in range(num_dirs):
        directories.append((_u32(data, dd_off + 8 * index), _u32(data, dd_off + 8 * index + 4)))
    sec_off = opt_off + opt_size
    if sec_off + 40 * num_sections > len(data):
        raise AnalysisError("truncated section table")
    sections: list[tuple[int, int, int, int]] = []
    for index in range(num_sections):
        base = sec_off + 40 * index
        sections.append(
            (
                _u32(data, base + 12),
                _u32(data, base + 8),
                _u32(data, base + 20),
                _u32(data, base + 16),
            )
        )
    return _PeImage(directories=tuple(directories), sections=tuple(sections))


def _rva_to_offset(image: _PeImage, rva: int) -> int | None:
    """Map an RVA into file bytes via the section table. ``None`` when unmapped."""
    for va, vsize, offset, rawsize in image.sections:
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= rawsize:
                return None  # virtual tail: no file bytes exist
            return offset + delta
    return None


# ---- delay-load parsing --------------------------------------------------------


def _desc_field(blob: bytes, base: int, offset: int, width: int) -> int:
    """Read one descriptor field, raising when it runs past the directory."""
    if base + offset + width > len(blob):
        raise AnalysisError(
            f"delay-load descriptor truncated: field at 0x{base + offset:x} "
            "runs past the directory bytes"
        )
    return int.from_bytes(blob[base + offset : base + offset + width], "little")


def _looks_like_v2(blob: bytes) -> bool:
    """Heuristic: v2 descriptors' 64-bit pointer fields have zero upper halves."""
    if len(blob) < V2_SIZE:
        return False
    return all(
        int.from_bytes(blob[base + 4 : base + 8], "little") == 0
        for base in (8, 16, 24, 32, 40, 48)
    )


def _pick_layout(blob: bytes, warnings: list[str]) -> tuple[int, str, int]:
    """Choose (stride, version label, thunk width) for the descriptor array.

    A directory whose size fits only v1 strides is v1; a whole-number-of-64
    directory whose first descriptor's 64-bit upper halves are zero is v2.
    Anything else is read as v1 with the trailing bytes ignored (warned).
    """
    if len(blob) >= V2_SIZE and len(blob) % V2_SIZE == 0 and _looks_like_v2(blob):
        return V2_SIZE, "v2", 8
    if len(blob) % V1_SIZE == 0:
        return V1_SIZE, "v1", 4
    warnings.append(
        f"delay-load directory size {len(blob)} is not a multiple of the "
        f"v1 descriptor size {V1_SIZE}; trailing bytes ignored"
    )
    return V1_SIZE, "v1", 4


def _read_name(data: bytes, image: _PeImage, index: int, address: int) -> str:
    """Read one NUL-terminated ASCII name at an RVA (bounded, typed errors)."""
    if address == 0:
        raise AnalysisError(f"delay-load descriptor {index} has a NULL DLL-name pointer")
    off = _rva_to_offset(image, address)
    if off is None:
        raise AnalysisError(
            f"delay-load descriptor {index} DLL name RVA 0x{address:x} "
            "is not mapped to file bytes"
        )
    chunk = data[off : off + MAX_NAME_CHARS + 1]
    nul = chunk.find(b"\x00")
    if nul < 0:
        raise AnalysisError(
            f"delay-load descriptor {index} DLL name at RVA 0x{address:x} is not "
            f"NUL-terminated within {MAX_NAME_CHARS} bytes"
        )
    return chunk[:nul].decode("ascii", "replace")


def _import_by_name(
    data: bytes, image: _PeImage, index: int, dll: str, thunk: int, width: int
) -> str:
    """Decode one INT entry: ordinal import or IMAGE_IMPORT_BY_NAME."""
    ordinal_flag = 1 << (8 * width - 1)
    if thunk & ordinal_flag:
        return f"#{thunk & (ordinal_flag - 1)}"
    off = _rva_to_offset(image, thunk)
    if off is None:
        raise AnalysisError(
            f"delay-load descriptor {index} ({dll}) IMAGE_IMPORT_BY_NAME RVA "
            f"0x{thunk:x} is not mapped to file bytes"
        )
    if off + 2 > len(data):
        raise AnalysisError(
            f"delay-load descriptor {index} ({dll}) hint/name entry at RVA "
            f"0x{thunk:x} is truncated"
        )
    chunk = data[off + 2 : off + 2 + MAX_NAME_CHARS + 1]
    nul = chunk.find(b"\x00")
    if nul < 0:
        raise AnalysisError(
            f"delay-load descriptor {index} ({dll}) import name at RVA 0x{thunk:x} "
            f"is not NUL-terminated within {MAX_NAME_CHARS} bytes"
        )
    return chunk[:nul].decode("ascii", "replace")


def _read_int(
    data: bytes,
    image: _PeImage,
    index: int,
    dll: str,
    int_rva: int,
    iat_rva: int,
    width: int,
    warnings: list[str],
) -> tuple[list[str], int, bool]:
    """Walk one descriptor's import-name table until NULL (bounded, honest)."""
    table_rva = int_rva
    if table_rva == 0:
        if iat_rva == 0:
            warnings.append(f"descriptor {index} ({dll}): no INT and no IAT; names unknown")
            return [], 0, False
        warnings.append(f"descriptor {index} ({dll}): no INT; walking the IAT contents instead")
        table_rva = iat_rva
    off = _rva_to_offset(image, table_rva)
    if off is None:
        raise AnalysisError(
            f"delay-load descriptor {index} ({dll}) INT RVA 0x{table_rva:x} "
            "is not mapped to file bytes"
        )
    names: list[str] = []
    total = 0
    cursor = off
    while cursor + width <= len(data):
        thunk = int.from_bytes(data[cursor : cursor + width], "little")
        if thunk == 0:
            break
        total += 1
        if len(names) < MAX_IMPORTS_PER_DLL:
            names.append(_import_by_name(data, image, index, dll, thunk, width))
        cursor += width
    truncated = total > MAX_IMPORTS_PER_DLL
    if truncated:
        warnings.append(
            f"descriptor {index} ({dll}): import list truncated at {MAX_IMPORTS_PER_DLL} "
            f"entries ({total} total)"
        )
    return names, total, truncated


def _empty_summary() -> DelayLoadSummary:
    return DelayLoadSummary(
        path="",
        delay_load_present=False,
        descriptor_count=0,
        descriptors=(),
        descriptors_truncated=False,
        import_count=0,
        import_total=0,
        warnings=(),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method=f"data-directory-{DIRECTORY_INDEX}-empty",
            confidence=Confidence.HIGH,
            detail="PE has no delay-load import directory",
        ),
    )


def _parse_delay_loads(data: bytes, image: _PeImage, warnings: list[str]) -> DelayLoadSummary:
    """Parse the delay-import directory payload (bounded, defensive)."""
    if len(image.directories) <= DIRECTORY_INDEX:
        return _empty_summary()
    dir_rva, dir_size = image.directories[DIRECTORY_INDEX]
    if dir_rva == 0 or dir_size == 0:
        return _empty_summary()
    dir_off = _rva_to_offset(image, dir_rva)
    if dir_off is None:
        raise AnalysisError(
            f"delay-load directory RVA 0x{dir_rva:x} is not mapped to file bytes"
        )
    blob = data[dir_off : dir_off + min(dir_size, MAX_DLLS * V2_SIZE)]
    stride, version, thunk_width = _pick_layout(blob, warnings)
    if len(blob) < stride:
        raise AnalysisError(
            f"delay-load descriptor truncated: directory holds {len(blob)} bytes at "
            f"RVA 0x{dir_rva:x}, one {version} descriptor needs {stride}"
        )
    slots = len(blob) // stride
    descriptors_truncated = slots > MAX_DLLS
    if descriptors_truncated:
        warnings.append(
            f"delay-load descriptor list truncated at {MAX_DLLS} descriptors ({slots} total)"
        )
    descriptors: list[dict[str, Any]] = []
    import_count = 0
    import_total = 0
    for index in range(min(slots, MAX_DLLS)):
        base = index * stride
        gr_attrs = _desc_field(blob, base, 0, 4)
        if version == "v2":
            sz_name, _hmod, p_iat, p_int, _bound, _unload = (
                _desc_field(blob, base, offset, 8) for offset in (8, 16, 24, 32, 40, 48)
            )
        else:
            sz_name, _hmod, p_iat, p_int, _bound, _unload = (
                _desc_field(blob, base, offset, 4) for offset in (4, 8, 12, 16, 20, 24)
            )
        if gr_attrs == 0 and sz_name == 0 and p_iat == 0 and p_int == 0:
            break  # NULL terminator slot ends the array
        if not gr_attrs & DLATTR_RVA:
            warnings.append(
                f"descriptor {index}: grAttrs lacks dlattrRva; bind-time VA fields "
                "are treated as RVAs (approximation)"
            )
        unknown = gr_attrs & ~KNOWN_ATTR_MASK
        if unknown:
            warnings.append(f"descriptor {index}: unknown grAttrs bits {unknown:#x}")
        traits = tuple(name for bit, name in GR_ATTR_NAMES.items() if gr_attrs & bit)
        dll = _read_name(data, image, index, sz_name)
        names, total, imports_truncated = _read_int(
            data, image, index, dll, p_int, p_iat, thunk_width, warnings
        )
        descriptors.append(
            {
                "index": index,
                "dll_name": dll,
                "gr_attrs": gr_attrs,
                "gr_attr_names": list(traits),
                "version": version,
                "iat_rva": p_iat,
                "int_rva": p_int,
                "imports": names,
                "imports_truncated": imports_truncated,
                "import_total": total,
            }
        )
        import_count += len(names)
        import_total += total
    detail = (
        f"{len(descriptors)} delay-load descriptor(s), {import_total} import(s) "
        f"({version} layout)"
    )
    return DelayLoadSummary(
        path="",
        delay_load_present=True,
        descriptor_count=len(descriptors),
        descriptors=tuple(descriptors),
        descriptors_truncated=descriptors_truncated,
        import_count=import_count,
        import_total=import_total,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="delay-import-directory-walk",
            confidence=Confidence.HIGH,
            detail=detail,
            extra={"rva": dir_rva, "size": dir_size},
        ),
    )


def inspect_delay_loads(path: str | Path) -> DelayLoadSummary:
    """Parse one PE file's delay-load import directory (pure Python, offline).

    Raises:
        AnalysisError: When the file is missing, is not a PE, is truncated
            mid-header, a delay-load descriptor is truncated, or a DLL-name,
            INT or IMAGE_IMPORT_BY_NAME RVA cannot be mapped to file bytes.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    image = _parse_pe_image(data)
    warnings: list[str] = []
    summary = _parse_delay_loads(data, image, warnings)
    return dataclasses.replace(summary, path=str(target))




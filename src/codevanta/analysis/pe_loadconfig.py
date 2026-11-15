"""Pure-Python PE load-config parser (lane-depth2).

Reads the ``IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`` directory (index 10) of a
PE32/PE32+ image plus the TLS directory (index 9) and the
``DllCharacteristics`` security bits, and returns a typed
:class:`PeLoadConfigSummary`:

* ``TLS`` callback list (bounded 16, resolved through the section table);
* Control Flow Guard facts: the ``GuardCFFunctionTable`` count and the
  decoded ``GuardFlags`` bits;
* the DEP policy (``NX_COMPAT``/``DYNAMIC_BASE``/``IMAGE_DLLCHARACTERISTICS_GUARD_CF``);
* the ``SEHandlerTable`` handler count.

A PE without a load-config directory is normal and yields a summary with
``load_config_present=False``; a malformed directory, an unmapped TLS
callback table or an unreadable callback array raise the typed
:class:`~codevanta.core.report.AnalysisError`. Parse-only: nothing here
evaluates the security posture, it reports what the header declares.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "GUARD_FLAG_NAMES",
    "MAX_TLS_CALLBACKS",
    "PeLoadConfigSummary",
    "inspect_pe_load_config",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "meta.pe-loadconfig"

#: TLS callback addresses kept (bounded work).
MAX_TLS_CALLBACKS = 16

#: Load-config bytes the parser ever looks at (bounded work).
MAX_LOAD_CONFIG_BYTES = 4096

#: ``IMAGE_GUARD`` flag bits (winnt.h ``IMAGE_GUARD*``, spec values).
GUARD_FLAG_NAMES: dict[int, str] = {
    0x100: "CF_INSTRUMENTED",
    0x200: "CFW_INSTRUMENTED",
    0x400: "CF_FUNCTION_TABLE_PRESENT",
    0x800: "SECURITY_COOKIE_UNUSED",
    0x1000: "PROTECT_DELAYLOAD_IAT",
    0x2000: "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
    0x4000: "CF_EXPORT_SUPPRESSION_INFO_PRESENT",
    0x8000: "CF_ENABLE_EXPORT_SUPPRESSION",
    0x10000: "CF_LONGJUMP_TABLE_PRESENT",
}

#: ``DllCharacteristics`` bits this summary reports as the DEP/CF policy.
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_NX_COMPAT = 0x0200
DLLCHAR_NO_SEH = 0x0400
DLLCHAR_GUARD_CF = 0x4000


# ---- typed results -----------------------------------------------------------


@dataclass(frozen=True)
class PeLoadConfigSummary:
    """Deep view of one PE's load config. Parse-only, bounded."""

    path: str
    load_config_present: bool
    config_size: int | None
    config_version: str | None
    dep_nx_compat: bool
    dep_dynamic_base: bool
    guard_cf_dllcharacteristics: bool
    dep_policy: str
    guard_flags: int | None
    guard_flag_names: tuple[str, ...]
    guard_cf_function_count: int | None
    guard_cf_function_table_rva: int | None
    seh_handler_count: int | None
    seh_handler_table_rva: int | None
    security_cookie: int | None
    tls_callback_count: int
    tls_callbacks: tuple[int, ...]
    tls_callbacks_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "load_config_present": self.load_config_present,
            "config_size": self.config_size,
            "config_version": self.config_version,
            "dep_nx_compat": self.dep_nx_compat,
            "dep_dynamic_base": self.dep_dynamic_base,
            "guard_cf_dllcharacteristics": self.guard_cf_dllcharacteristics,
            "dep_policy": self.dep_policy,
            "guard_flags": self.guard_flags,
            "guard_flag_names": list(self.guard_flag_names),
            "guard_cf_function_count": self.guard_cf_function_count,
            "guard_cf_function_table_rva": self.guard_cf_function_table_rva,
            "seh_handler_count": self.seh_handler_count,
            "seh_handler_table_rva": self.seh_handler_table_rva,
            "security_cookie": self.security_cookie,
            "tls_callback_count": self.tls_callback_count,
            "tls_callbacks": [f"0x{va:x}" for va in self.tls_callbacks],
            "tls_callbacks_truncated": self.tls_callbacks_truncated,
            "warnings": list(self.warnings),
        }


# ---- PE header walking -------------------------------------------------------


@dataclass(frozen=True)
class _PeImage:
    """The few PE header facts the load-config parser needs (validated)."""

    opt_magic: int
    dll_characteristics: int
    entry_point: int
    sections: tuple[tuple[int, int, int, int], ...]  # (va, vsize, off, rawsize)
    directories: tuple[tuple[int, int], ...]  # (rva, size) per index


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AnalysisError(f"truncated PE image: read past EOF at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


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
    dll_characteristics = _u16(data, opt_off + 70)
    entry_point = _u32(data, opt_off + 16)
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
    return _PeImage(
        opt_magic=opt_magic,
        dll_characteristics=dll_characteristics,
        entry_point=entry_point,
        sections=tuple(sections),
        directories=tuple(directories),
    )


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


# ---- load-config + TLS parsing ------------------------------------------------


def _dep_policy(bits: int) -> str:
    """Derive the honest policy label from the ``DllCharacteristics`` word."""
    if not bits & DLLCHAR_NX_COMPAT:
        return "nx-not-declared"
    parts = ["nx"]
    if bits & DLLCHAR_DYNAMIC_BASE:
        parts.append("aslr")
    if bits & DLLCHAR_GUARD_CF:
        parts.append("cfguard")
    if bits & DLLCHAR_NO_SEH:
        parts.append("no-seh")
    return "+".join(parts)


def _config_field(blob: bytes, offset32: int, offset64: int, is64: bool) -> int | None:
    """Read one load-config field by its 32/64-bit offset. ``None`` when absent.

    The claimed ``Size`` field governs which fields exist; a directory that
    predates a field simply does not carry it.
    """
    offset = offset64 if is64 else offset32
    width = 8 if is64 else 4
    if offset + width > len(blob):
        return None
    return int.from_bytes(blob[offset : offset + width], "little")


def _read_tls_callbacks(
    data: bytes, image: _PeImage, warnings: list[str]
) -> tuple[tuple[int, ...], int, bool]:
    """Walk the ``AddressOfCallBacks`` pointer array (keep 16, count honestly)."""
    if len(image.directories) <= 9:
        return (), 0, False
    tls_rva, tls_size = image.directories[9]
    if tls_rva == 0 or tls_size == 0:
        return (), 0, False
    is64 = image.opt_magic == 0x20B
    tls_off = _rva_to_offset(image, tls_rva)
    if tls_off is None:
        warnings.append(f"TLS directory RVA 0x{tls_rva:x} is not mapped; callbacks unknown")
        return (), 0, False
    ptr_off = tls_off + (24 if is64 else 12)
    width = 8 if is64 else 4
    if ptr_off + width > len(data):
        raise AnalysisError("TLS directory truncated before AddressOfCallBacks")
    callbacks_va = int.from_bytes(data[ptr_off : ptr_off + width], "little")
    if callbacks_va == 0:
        return (), 0, False
    array_off = _rva_to_offset(image, callbacks_va)
    if array_off is None:
        raise AnalysisError(f"TLS callback array VA 0x{callbacks_va:x} is not mapped")
    callbacks: list[int] = []
    total = 0
    cursor = array_off
    while cursor + width <= len(data):
        entry = int.from_bytes(data[cursor : cursor + width], "little")
        if entry == 0:
            break
        total += 1
        if total <= MAX_TLS_CALLBACKS:
            callbacks.append(entry)
        cursor += width
    truncated = total > MAX_TLS_CALLBACKS
    if truncated:
        warnings.append(f"TLS callback list truncated at {MAX_TLS_CALLBACKS} entries")
    return tuple(callbacks), total, truncated


def _empty_summary(bits: int, warnings: list[str]) -> PeLoadConfigSummary:
    return PeLoadConfigSummary(
        path="",
        load_config_present=False,
        config_size=None,
        config_version=None,
        dep_nx_compat=bool(bits & DLLCHAR_NX_COMPAT),
        dep_dynamic_base=bool(bits & DLLCHAR_DYNAMIC_BASE),
        guard_cf_dllcharacteristics=bool(bits & DLLCHAR_GUARD_CF),
        dep_policy=_dep_policy(bits),
        guard_flags=None,
        guard_flag_names=(),
        guard_cf_function_count=None,
        guard_cf_function_table_rva=None,
        seh_handler_count=None,
        seh_handler_table_rva=None,
        security_cookie=None,
        tls_callback_count=0,
        tls_callbacks=(),
        tls_callbacks_truncated=False,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="data-directory-10-empty",
            confidence=Confidence.HIGH,
            detail="PE has no load-config directory",
        ),
    )


def _parse_load_config(
    data: bytes, image: _PeImage, warnings: list[str]
) -> PeLoadConfigSummary:
    """Parse the load-config directory payload (bounded, defensive)."""
    bits = image.dll_characteristics
    is64 = image.opt_magic == 0x20B
    if len(image.directories) <= 10:
        return _empty_summary(bits, warnings)
    lc_rva, lc_size = image.directories[10]
    if lc_rva == 0 or lc_size == 0:
        return _empty_summary(bits, warnings)
    lc_off = _rva_to_offset(image, lc_rva)
    if lc_off is None:
        raise AnalysisError(f"load-config RVA 0x{lc_rva:x} is not mapped to file bytes")
    blob = data[lc_off : lc_off + min(lc_size, MAX_LOAD_CONFIG_BYTES)]
    if len(blob) < 4:
        raise AnalysisError("load-config directory smaller than its Size field")
    (claimed,) = struct.unpack_from("<I", blob, 0)
    if claimed < 4 or claimed > len(blob):
        raise AnalysisError(
            f"load-config Size field {claimed} contradicts the directory bytes ({len(blob)})"
        )
    major = _config_field(blob, 8, 8, is64) or 0
    minor = _config_field(blob, 10, 10, is64) or 0
    guard_flags_offset = 148 if is64 else 88
    guard_flags = (
        int.from_bytes(blob[guard_flags_offset : guard_flags_offset + 4], "little")
        if guard_flags_offset + 4 <= len(blob)
        else None
    )
    guard_table = _config_field(blob, 80, 132, is64)
    guard_count = _config_field(blob, 84, 140, is64)
    seh_table = _config_field(blob, 64, 100, is64)
    seh_count = _config_field(blob, 68, 108, is64)
    cookie = _config_field(blob, 60, 92, is64)
    names = tuple(
        GUARD_FLAG_NAMES[bit]
        for bit in GUARD_FLAG_NAMES
        if guard_flags is not None and guard_flags & bit
    )
    if seh_count is not None and bits & DLLCHAR_NO_SEH:
        warnings.append("DllCharacteristics declares NO_SEH; the SE handler count is vestigial")
    detail = (
        f"size={claimed}, version={major}.{minor}, guard flags {guard_flags:#x}, "
        f"CF functions {guard_count}, SE handlers {seh_count}"
    )
    return PeLoadConfigSummary(
        path="",
        load_config_present=True,
        config_size=claimed,
        config_version=f"{major}.{minor}",
        dep_nx_compat=bool(bits & DLLCHAR_NX_COMPAT),
        dep_dynamic_base=bool(bits & DLLCHAR_DYNAMIC_BASE),
        guard_cf_dllcharacteristics=bool(bits & DLLCHAR_GUARD_CF),
        dep_policy=_dep_policy(bits),
        guard_flags=guard_flags,
        guard_flag_names=names,
        guard_cf_function_count=guard_count,
        guard_cf_function_table_rva=guard_table,
        seh_handler_count=seh_count,
        seh_handler_table_rva=seh_table,
        security_cookie=cookie,
        tls_callback_count=0,
        tls_callbacks=(),
        tls_callbacks_truncated=False,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="load-config-walk",
            confidence=Confidence.HIGH,
            detail=detail,
            extra={"rva": lc_rva, "size": lc_size},
        ),
    )


def inspect_pe_load_config(path: str | Path) -> PeLoadConfigSummary:
    """Parse one PE file's load config + TLS directory (pure Python, offline).

    Raises:
        AnalysisError: When the file is not a PE, is truncated mid-header,
            the load-config directory cannot be mapped, its ``Size`` field
            contradicts the payload, or the TLS callback array is unreadable.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    data = target.read_bytes()
    image = _parse_pe_image(data)
    warnings: list[str] = []
    summary = _parse_load_config(data, image, warnings)
    callbacks, tls_total, tls_truncated = _read_tls_callbacks(data, image, warnings)
    evidence = summary.evidence
    if callbacks:
        extra = dict(summary.evidence.extra or {})
        extra["tls_callbacks"] = tls_total
        evidence = Evidence(
            source=EVIDENCE_SOURCE,
            method=summary.evidence.method,
            confidence=Confidence.HIGH,
            detail=f"{summary.evidence.detail}; {tls_total} TLS callback(s)",
            extra=extra,
        )
    return PeLoadConfigSummary(
        path=str(target),
        load_config_present=summary.load_config_present,
        config_size=summary.config_size,
        config_version=summary.config_version,
        dep_nx_compat=summary.dep_nx_compat,
        dep_dynamic_base=summary.dep_dynamic_base,
        guard_cf_dllcharacteristics=summary.guard_cf_dllcharacteristics,
        dep_policy=summary.dep_policy,
        guard_flags=summary.guard_flags,
        guard_flag_names=summary.guard_flag_names,
        guard_cf_function_count=summary.guard_cf_function_count,
        guard_cf_function_table_rva=summary.guard_cf_function_table_rva,
        seh_handler_count=summary.seh_handler_count,
        seh_handler_table_rva=summary.seh_handler_table_rva,
        security_cookie=summary.security_cookie,
        tls_callback_count=tls_total,
        tls_callbacks=callbacks,
        tls_callbacks_truncated=tls_truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )

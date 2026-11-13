"""DWARF debug-info extraction via the optional pyelftools backend.

Producer debug info is the strongest symbol evidence available for a build
that kept it: real function names, byte-exact extents, and data-type layouts
straight from the compiler. This module reads ``.debug_info`` through
:mod:`elftools` (pyelftools), an **optional** dependency:

    pip install -e ".[dwarf]"      # or ".[dev]" for CI

When the extra is missing, :func:`extract_debug_info` raises
:class:`~codevanta.core.report.AnalysisError` naming the extra — the same
graceful-refusal contract as the decompiler providers (#32).

Scope (stated honestly):
* ELF only. pyelftools reads the ELF container; PE/Mach-O are rejected with a
  typed message rather than half-parsed.
* DWARF v2-5 via pyelftools; ``.debug_info`` DIEs only. No line tables, no
  inline chains, no expression evaluation.
* PDB (PE) is out of scope here — the LIEF OSS build gates its PDB parser
  behind the Extended distribution, so there is no OSS backend to wrap yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "DebugFunction",
    "DebugType",
    "DebugInfoResult",
    "extract_debug_info",
]

#: Default cap on returned debug functions (mirrors ``functions`` defaults).
DEFAULT_LIMIT = 500

#: Hard ceiling accepted for ``limit`` (bounded-resource rule).
MAX_LIMIT = 100_000

#: DIE tags mapped to a short kind label for type entries.
_TYPE_KINDS = {
    "DW_TAG_structure_type": "struct",
    "DW_TAG_union_type": "union",
    "DW_TAG_enumeration_type": "enum",
    "DW_TAG_class_type": "class",
}


@dataclass(frozen=True)
class DebugFunction:
    """One DWARF subprogram: producer-grade name and byte-exact extent."""

    name: str
    address: int
    size: int
    linkage_name: str | None
    is_external: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "address": f"0x{self.address:x}",
            "size": self.size,
            "is_external": self.is_external,
            "evidence": self.evidence.to_dict(),
        }
        if self.linkage_name is not None:
            data["linkage_name"] = self.linkage_name
        return data


@dataclass(frozen=True)
class DebugType:
    """One named data-type layout from the producer (struct/union/enum/class)."""

    name: str
    kind: str
    byte_size: int
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "byte_size": self.byte_size,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class DebugInfoResult:
    """Everything ``.debug_info`` yielded, with counts and truncation flags."""

    functions: list[DebugFunction]
    types: list[DebugType]
    truncated_functions: bool
    truncated_types: bool
    evidence: Evidence
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_count": len(self.functions),
            "type_count": len(self.types),
            "truncated_functions": self.truncated_functions,
            "truncated_types": self.truncated_types,
            "functions": [f.to_dict() for f in self.functions],
            "types": [t.to_dict() for t in self.types],
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _require_elf(info: BinaryInfo) -> None:
    if info.format != "ELF":
        raise AnalysisError(
            f"debug-info extraction supports ELF only, got {info.format!r}; "
            "PE PDB parsing needs a backend that is not available yet"
        )


def _load_elftools(path: Path):
    """Import pyelftools lazily and open ``path``; refuse with a typed error."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise AnalysisError(
            "pyelftools is not installed: run pip install -e \".[dwarf]\" "
            "(or .[dev]) to enable debug-info extraction"
        ) from exc
    handle = path.open("rb")
    try:
        return ELFFile(handle), handle
    except Exception:
        handle.close()
        raise


def extract_debug_info(
    path: str | Path,
    info: BinaryInfo,
    *,
    limit: int = DEFAULT_LIMIT,
) -> DebugInfoResult:
    """Extract named functions and data-type layouts from ELF DWARF.

    Args:
        path: File the metadata in ``info`` was loaded from (read-only).
        info: Normalized binary metadata; must be an ELF.
        limit: Cap on functions and types returned each (1..100000).

    Returns:
        A :class:`DebugInfoResult`; empty lists with warnings when the binary
        carries no ``.debug_info``.

    Raises:
        AnalysisError: If the binary is not an ELF, ``limit`` is out of range,
            or pyelftools is not installed.
    """
    if limit < 1:
        raise AnalysisError("limit must be >= 1")
    if limit > MAX_LIMIT:
        raise AnalysisError(f"limit too large (limit {MAX_LIMIT})")
    _require_elf(info)

    elf_file, handle = _load_elftools(Path(path))
    try:
        if not elf_file.has_dwarf_info():
            return DebugInfoResult(
                functions=[],
                types=[],
                truncated_functions=False,
                truncated_types=False,
                evidence=Evidence(
                    source="dwarf.debug_info",
                    method="elf_scan",
                    confidence=Confidence.HIGH,
                    detail="binary carries no DWARF debug info",
                ),
                warnings=("no .debug_info section in this ELF",),
            )

        dwarf_info = elf_file.get_dwarf_info()
        functions: list[DebugFunction] = []
        types: list[DebugType] = []
        warnings: list[str] = []
        truncated_functions = False
        truncated_types = False

        for cu in dwarf_info.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    if truncated_functions:
                        continue
                    low_attr = die.attributes.get("DW_AT_low_pc")
                    decl_attr = die.attributes.get("DW_AT_declaration")
                    if low_attr is None or decl_attr is not None:
                        continue  # prototype or outlined without a body here
                    name_attr = die.attributes.get("DW_AT_name")
                    name = (
                        str(name_attr.value, "utf-8", "replace")
                        if name_attr is not None
                        else ""
                    )
                    if not name:
                        continue
                    high_attr = die.attributes.get("DW_AT_high_pc")
                    if high_attr is None:
                        size = 0
                    elif high_attr.form == "DW_FORM_addr":
                        size = max(0, int(high_attr.value) - int(low_attr.value))
                    else:
                        # data forms store an offset from low_pc
                        size = int(high_attr.value)
                    linkage = die.attributes.get("DW_AT_MIPS_linkage_name") or die.attributes.get(
                        "DW_AT_linkage_name"
                    )
                    functions.append(
                        DebugFunction(
                            name=name,
                            address=int(low_attr.value),
                            size=size,
                            linkage_name=(
                                str(linkage.value, "utf-8", "replace")
                                if linkage is not None
                                else None
                            ),
                            is_external=bool(
                                die.attributes.get("DW_AT_external") is not None
                            ),
                            evidence=Evidence(
                                source="dwarf.debug_info",
                                method="DIE_subprogram",
                                confidence=Confidence.HIGH,
                                address=int(low_attr.value),
                                detail=f"{name}: DWARF subprogram, {size} bytes",
                            ),
                        )
                    )
                    if len(functions) >= limit:
                        truncated_functions = True

                elif die.tag in _TYPE_KINDS:
                    if truncated_types:
                        continue
                    name_attr = die.attributes.get("DW_AT_name")
                    size_attr = die.attributes.get("DW_AT_byte_size")
                    if name_attr is None or size_attr is None:
                        continue  # anonymous or declaration-only layout
                    types.append(
                        DebugType(
                            name=str(name_attr.value, "utf-8", "replace"),
                            kind=_TYPE_KINDS[die.tag],
                            byte_size=int(size_attr.value),
                            evidence=Evidence(
                                source="dwarf.debug_info",
                                method="DIE_structure_type"
                                if die.tag == "DW_TAG_structure_type"
                                else "DIE_type",
                                confidence=Confidence.HIGH,
                                detail=(
                                    f"{str(name_attr.value, 'utf-8', 'replace')}: "
                                    f"{_TYPE_KINDS[die.tag]}, {int(size_attr.value)} bytes"
                                ),
                            ),
                        )
                    )
                    if len(types) >= limit:
                        truncated_types = True
    finally:
        handle.close()

    warnings = []
    if truncated_functions:
        warnings.append(f"function limit {limit} reached; more subprograms exist")
    if truncated_types:
        warnings.append(f"type limit {limit} reached; more named types exist")

    return DebugInfoResult(
        functions=functions,
        types=types,
        truncated_functions=truncated_functions,
        truncated_types=truncated_types,
        evidence=Evidence(
            source="dwarf.debug_info",
            method="debug_info_scan",
            confidence=Confidence.HIGH,
            detail=(
                f"{len(functions)} DWARF function(s), {len(types)} named type(s); "
                "producer metadata, highest-grade symbol evidence"
            ),
        ),
        warnings=tuple(warnings),
    )

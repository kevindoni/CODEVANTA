"""Binary loading and metadata extraction backed by LIEF.

The loader normalizes PE, ELF, and Mach-O binaries into :class:`BinaryInfo`.
All addresses exposed by ``BinaryInfo`` are absolute virtual addresses (VA);
PE RVAs are rebased with the image base so downstream modules can treat every
format uniformly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief

from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

try:  # keep expected parser warnings (e.g. section-only ELF) out of stderr
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except Exception:  # pragma: no cover - LIEF build without logging controls
    pass



class BinaryLoadError(Exception):
    """Raised when a file cannot be loaded as a supported binary."""


@dataclass(frozen=True)
class SectionInfo:
    """A section with a known file mapping."""

    name: str
    virtual_address: int
    size: int
    offset: int
    raw_size: int = 0
    entropy: float | None = None
    is_executable: bool = False
    is_writable: bool = False
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:x}",
            "size": self.size,
            "raw_size": self.raw_size,
            "offset": f"0x{self.offset:x}",
            "entropy": self.entropy,
            "executable": self.is_executable,
            "writable": self.is_writable,
        }
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


@dataclass(frozen=True)
class ImportInfo:
    """An imported symbol."""

    name: str
    library: str | None = None
    address: int | None = None
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.library:
            data["library"] = self.library
        if self.address is not None:
            data["address"] = f"0x{self.address:x}"
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


@dataclass(frozen=True)
class ExportInfo:
    """An exported symbol, with forwarding information when present."""

    name: str
    address: int | None
    ordinal: int | None = None
    forwarded_to: str | None = None
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.address is not None:
            data["address"] = f"0x{self.address:x}"
        if self.ordinal is not None:
            data["ordinal"] = self.ordinal
        if self.forwarded_to:
            data["forwarded_to"] = self.forwarded_to
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


@dataclass(frozen=True)
class SymbolInfo:
    """A symbol from a symbol table (ELF symtab/dynsym, PE COFF)."""

    name: str
    address: int
    size: int = 0
    kind: str = "unknown"
    is_function: bool = False
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "address": f"0x{self.address:x}",
            "size": self.size,
            "kind": self.kind,
            "is_function": self.is_function,
        }
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


@dataclass
class BinaryInfo:
    """Normalized metadata for a loaded binary. All addresses are VA."""

    path: Path
    format: str
    architecture: str
    bitness: int
    endianness: str
    entry_point: int | None
    image_base: int
    sha256: str
    file_size: int
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)
    is_stripped: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "format": self.format,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "endianness": self.endianness,
            "entry_point": f"0x{self.entry_point:x}" if self.entry_point is not None else None,
            "image_base": f"0x{self.image_base:x}",
            "sha256": self.sha256,
            "file_size": self.file_size,
            "is_stripped": self.is_stripped,
            "sections": [s.to_dict() for s in self.sections],
            "imports": [i.to_dict() for i in self.imports],
            "exports": [e.to_dict() for e in self.exports],
            "symbols": [s.to_dict() for s in self.symbols],
            "warnings": list(self.warnings),
        }

    def section_for_va(self, va: int) -> SectionInfo | None:
        """Return the section that contains ``va``, if any."""
        for section in self.sections:
            if section.size <= 0:
                continue
            if section.virtual_address <= va < section.virtual_address + section.size:
                return section
        return None

    def _mapped_size(self, section: SectionInfo) -> int:
        if section.raw_size > 0:
            return section.raw_size
        if self.format == "ELF":
            return section.size
        return 0

    def va_to_offset(self, va: int) -> int | None:
        """Map a virtual address to a file offset using section metadata."""
        section = self.section_for_va(va)
        if section is None:
            return None
        delta = va - section.virtual_address
        mapped = self._mapped_size(section)
        if mapped <= 0 or delta < 0 or delta >= mapped:
            return None
        return section.offset + delta

    def offset_to_va(self, offset: int) -> int | None:
        """Map a file offset to a virtual address using section metadata."""
        for section in self.sections:
            mapped = self._mapped_size(section)
            if mapped <= 0:
                continue
            if section.offset <= offset < section.offset + mapped:
                return section.virtual_address + (offset - section.offset)
        return None


class BinaryLoader:
    """Loads PE, ELF, and Mach-O binaries and extracts structural metadata."""

    MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 MiB safety guard

    def load(self, path: str | Path) -> BinaryInfo:
        """Load ``path`` and return normalized :class:`BinaryInfo`."""
        file_path = Path(path)
        self._validate(file_path)
        raw = file_path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        try:
            binary = lief.parse(str(file_path))
        except Exception as exc:  # LIEF raises several native error types
            raise BinaryLoadError(f"LIEF could not parse {file_path}: {exc}") from exc
        if binary is None:
            raise BinaryLoadError(f"Unsupported or unreadable binary: {file_path}")

        fmt = self._format_name(binary)
        if fmt == "PE":
            info = self._load_pe(binary, file_path)
        elif fmt == "ELF":
            info = self._load_elf(binary, file_path)
        elif fmt == "MachO":
            info = self._load_macho(binary, file_path)
        else:
            raise BinaryLoadError(f"Unsupported format {fmt!r}: {file_path}")

        info.sha256 = sha256
        info.file_size = len(raw)
        return info

    @staticmethod
    def _validate(path: Path) -> None:
        if not path.exists():
            raise BinaryLoadError(f"File not found: {path}")
        if not path.is_file():
            raise BinaryLoadError(f"Not a regular file: {path}")
        size = path.stat().st_size
        if size == 0:
            raise BinaryLoadError(f"Empty file: {path}")
        if size > BinaryLoader.MAX_FILE_SIZE:
            raise BinaryLoadError(
                f"File too large ({size} bytes); limit is {BinaryLoader.MAX_FILE_SIZE} bytes"
            )

    @staticmethod
    def _format_name(binary: Any) -> str:
        text = str(getattr(binary, "format", "")).upper()
        if "ELF" in text:
            return "ELF"
        if "PE" in text:
            return "PE"
        if "MACHO" in text or "MACH_O" in text:
            return "MachO"
        type_name = type(binary).__name__.upper()
        if "ELF" in type_name:
            return "ELF"
        if "PE" in type_name:
            return "PE"
        return "Unknown"

    # ---- PE ---------------------------------------------------------------

    def _load_pe(self, binary: Any, path: Path) -> BinaryInfo:
        optional = getattr(binary, "optional_header", None)
        image_base = self._as_int(getattr(optional, "imagebase", 0))
        entry_rva = self._as_int(getattr(optional, "addressof_entrypoint", 0))
        entry_va = image_base + entry_rva if entry_rva else None
        header = getattr(binary, "header", None)
        machine = str(self._get_attr(header, "machine", "machine_type") or "")
        arch, bitness = self._pe_arch(machine)
        sections = [self._pe_section(s, image_base) for s in self._safe(binary, "sections")]
        imports = self._pe_imports(binary, image_base)
        exports = self._pe_exports(binary, image_base)
        symbols = self._pe_symbols(binary)
        warnings: list[str] = []
        if not exports and not symbols:
            warnings.append(
                "No exports or symbols found; function discovery is limited to the entry point."
            )
        return BinaryInfo(
            path=path,
            format="PE",
            architecture=arch,
            bitness=bitness,
            endianness="little",
            entry_point=entry_va,
            image_base=image_base,
            sha256="",
            file_size=0,
            sections=sections,
            imports=imports,
            exports=exports,
            symbols=symbols,
            is_stripped=not symbols and not exports,
            warnings=warnings,
        )

    @staticmethod
    def _pe_arch(machine: str) -> tuple[str, int]:
        upper = machine.upper()
        if "AMD64" in upper or "X86_64" in upper:
            return "x86_64", 64
        if "I386" in upper or "I686" in upper:
            return "x86", 32
        if "AARCH64" in upper or "ARM64" in upper:
            return "aarch64", 64
        if "ARM" in upper:
            return "arm", 32
        if "IA64" in upper:
            return "ia64", 64
        return "unknown", 0

    @classmethod
    def _pe_section(cls, section: Any, image_base: int) -> SectionInfo:
        characteristics = cls._as_int(getattr(section, "characteristics", 0))
        entropy = getattr(section, "entropy", None)
        virtual_size = cls._as_int(getattr(section, "virtual_size", 0))
        size = virtual_size or cls._as_int(getattr(section, "size", 0))
        return SectionInfo(
            name=str(getattr(section, "name", "") or ""),
            virtual_address=image_base + cls._as_int(getattr(section, "virtual_address", 0)),
            size=size,
            offset=cls._as_int(getattr(section, "offset", 0)),
            raw_size=cls._as_int(getattr(section, "sizeof_raw_data", 0)),
            entropy=float(entropy) if entropy is not None else None,
            is_executable=bool(characteristics & 0x20000000),
            is_writable=bool(characteristics & 0x80000000),
            evidence=Evidence(
                source="pe.section_table",
                method="section_header",
                confidence=Confidence.CERTAIN,
                address=image_base + cls._as_int(getattr(section, "virtual_address", 0)),
                detail=f"PE section {getattr(section, 'name', '')!r}",
            ),
        )

    @classmethod
    def _pe_imports(cls, binary: Any, image_base: int) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        for lib in cls._safe(binary, "imports"):
            library = str(getattr(lib, "name", "") or "") or None
            for entry in getattr(lib, "entries", []) or []:
                name = str(getattr(entry, "name", "") or "")
                if not name and getattr(entry, "is_ordinal", False):
                    name = f"ordinal_{cls._as_int(getattr(entry, 'ordinal', 0))}"
                if not name:
                    continue
                iat = getattr(entry, "iat_address", None)
                address = image_base + cls._as_int(iat) if iat else None
                imports.append(
                    ImportInfo(
                        name=name,
                        library=library,
                        address=address,
                        evidence=Evidence(
                            source="pe.import_table",
                            method="import_directory",
                            confidence=Confidence.HIGH,
                            address=address,
                            detail=f"imported from {library or 'unknown module'}",
                        ),
                    )
                )
        return imports

    @classmethod
    def _pe_exports(cls, binary: Any, image_base: int) -> list[ExportInfo]:
        exports: list[ExportInfo] = []
        table = None
        getter = getattr(binary, "get_export", None) or getattr(binary, "export", None)
        if callable(getter):
            try:
                table = getter()
            except Exception:
                table = None
        entries = list(getattr(table, "entries", []) or []) if table is not None else []
        if entries:
            for entry in entries:
                name = str(getattr(entry, "name", "") or "")
                ordinal = getattr(entry, "ordinal", None)
                forwarded = bool(getattr(entry, "is_forwarded", False))
                forward_to = cls._pe_forward_target(entry)
                rva = getattr(entry, "function_rva", None)
                if not rva:
                    rva = getattr(entry, "address", None)
                address = image_base + cls._as_int(rva) if rva else None
                confidence = Confidence.HIGH if address is not None else Confidence.MEDIUM
                detail = "forwarded export" if forwarded else "exported function"
                evidence = Evidence(
                    source="pe.export_table",
                    method="export_directory",
                    confidence=confidence,
                    address=address,
                    detail=detail,
                )
                exports.append(
                    ExportInfo(
                        name=name or f"ordinal_{cls._as_int(ordinal)}",
                        address=address,
                        ordinal=cls._as_int(ordinal) if ordinal is not None else None,
                        forwarded_to=forward_to,
                        evidence=evidence,
                    )
                )
            return exports

        # Fallback for LIEF builds that only expose a name list.
        for item in cls._safe(binary, "exported_functions"):
            if isinstance(item, str):
                name, raw_address = item, None
            else:
                name = str(getattr(item, "name", "") or "")
                raw_address = getattr(item, "address", None)
            if not name:
                continue
            address = image_base + cls._as_int(raw_address) if raw_address else None
            evidence = Evidence(
                source="pe.exported_functions",
                method="export_list",
                confidence=Confidence.HIGH if address is not None else Confidence.MEDIUM,
                address=address,
                detail="exported function",
            )
            exports.append(ExportInfo(name=name, address=address, evidence=evidence))
        return exports

    @staticmethod
    def _pe_forward_target(entry: Any) -> str | None:
        info = getattr(entry, "forward_information", None)
        if info is None:
            return None
        library = getattr(info, "library", None)
        function = getattr(info, "function", None)
        if library and function:
            return f"{library}.{function}"
        return str(info) if info else None

    @classmethod
    def _pe_symbols(cls, binary: Any) -> list[SymbolInfo]:
        symbols: list[SymbolInfo] = []
        for symbol in cls._safe(binary, "symbols"):
            name = str(getattr(symbol, "name", "") or "")
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            size = cls._as_int(getattr(symbol, "size", 0))
            is_function = bool(getattr(symbol, "is_function", False))
            evidence = Evidence(
                source="pe.coff_symbols",
                method="symbol_table",
                confidence=Confidence.MEDIUM,
                address=value or None,
                detail="COFF symbol value may be section-relative",
            )
            symbols.append(
                SymbolInfo(
                    name=name,
                    address=value,
                    size=size,
                    kind="function" if is_function else "data",
                    is_function=is_function,
                    evidence=evidence,
                )
            )
        return symbols


    # ---- ELF --------------------------------------------------------------

    def _load_elf(self, binary: Any, path: Path) -> BinaryInfo:
        header = getattr(binary, "header", None)
        machine = str(self._get_attr(header, "machine_type", "machine") or "")
        arch, bitness = self._elf_arch(machine)
        class_text = str(self._get_attr(header, "identity_class", "") or "").upper()
        if "ELF64" in class_text:
            bitness = 64
        elif "ELF32" in class_text:
            bitness = 32
        data_text = str(self._get_attr(header, "identity_data", "") or "").upper()
        endianness = "big" if "MSB" in data_text else "little"
        image_base = self._as_int(getattr(binary, "imagebase", 0))
        if image_base < 0 or image_base >= (1 << 63):
            image_base = 0
        entry_point = self._as_int(getattr(binary, "entrypoint", 0)) or None
        sections = [self._elf_section(s) for s in self._safe(binary, "sections")]
        imports = self._elf_imports(binary)
        exports = self._elf_exports(binary)
        symbols = self._elf_symbols(binary)
        warnings: list[str] = []
        if not sections:
            warnings.append("ELF has no section headers; section-based analysis is limited.")
        if not symbols:
            warnings.append("Binary is stripped: no symbol table found.")
        return BinaryInfo(
            path=path,
            format="ELF",
            architecture=arch,
            bitness=bitness,
            endianness=endianness,
            entry_point=entry_point,
            image_base=image_base,
            sha256="",
            file_size=0,
            sections=sections,
            imports=imports,
            exports=exports,
            symbols=symbols,
            is_stripped=not symbols,
            warnings=warnings,
        )

    @staticmethod
    def _elf_arch(machine: str) -> tuple[str, int]:
        upper = machine.upper()
        if "X86_64" in upper or "AMD64" in upper:
            return "x86_64", 64
        if "I386" in upper or upper.endswith("386"):
            return "x86", 32
        if "AARCH64" in upper or "ARM64" in upper:
            return "aarch64", 64
        if "ARM" in upper:
            return "arm", 32
        if "MIPS" in upper:
            return "mips", 0
        return "unknown", 0

    @classmethod
    def _elf_section(cls, section: Any) -> SectionInfo:
        flags = cls._as_int(getattr(section, "flags", 0))
        entropy = getattr(section, "entropy", None)
        return SectionInfo(
            name=str(getattr(section, "name", "") or ""),
            virtual_address=cls._as_int(getattr(section, "virtual_address", 0)),
            size=cls._as_int(getattr(section, "size", 0)),
            offset=cls._as_int(getattr(section, "offset", 0)),
            raw_size=0,
            entropy=float(entropy) if entropy is not None else None,
            is_executable=bool(flags & 0x4),  # SHF_EXECINSTR
            is_writable=bool(flags & 0x1),    # SHF_WRITE
            evidence=Evidence(
                source="elf.section_table",
                method="section_header",
                confidence=Confidence.CERTAIN,
                address=cls._as_int(getattr(section, "virtual_address", 0)),
                detail=f"ELF section {getattr(section, 'name', '')!r}",
            ),
        )


    @classmethod
    def _elf_imports(cls, binary: Any) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        for symbol in cls._safe(binary, "imported_symbols"):
            name = str(getattr(symbol, "name", "") or "")
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            imports.append(
                ImportInfo(
                    name=name,
                    address=value or None,
                    evidence=Evidence(
                        source="elf.dynsym",
                        method="imported_symbol",
                        confidence=Confidence.HIGH,
                        address=value or None,
                        detail="imported dynamic symbol",
                    ),
                )
            )
        return imports

    @classmethod
    def _elf_exports(cls, binary: Any) -> list[ExportInfo]:
        exports: list[ExportInfo] = []
        for symbol in cls._safe(binary, "exported_symbols"):
            name = str(getattr(symbol, "name", "") or "")
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            evidence = Evidence(
                source="elf.dynsym",
                method="exported_symbol",
                confidence=Confidence.HIGH if value else Confidence.MEDIUM,
                address=value or None,
                detail="exported dynamic symbol",
            )
            exports.append(ExportInfo(name=name, address=value or None, evidence=evidence))
        return exports

    @classmethod
    def _elf_symbols(cls, binary: Any) -> list[SymbolInfo]:
        symbols: list[SymbolInfo] = []
        seen: set[tuple[str, int]] = set()
        for symbol in cls._safe(binary, "symbols"):
            name = str(getattr(symbol, "name", "") or "")
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            size = cls._as_int(getattr(symbol, "size", 0))
            type_text = str(getattr(symbol, "type", "") or "")
            is_function = "FUNC" in type_text.upper()
            evidence = Evidence(
                source="elf.symtab",
                method="symbol_table",
                confidence=Confidence.HIGH,
                address=value or None,
                detail="ELF symbol table entry",
            )
            symbols.append(
                SymbolInfo(
                    name=name,
                    address=value,
                    size=size,
                    kind=type_text or "unknown",
                    is_function=is_function,
                    evidence=evidence,
                )
            )
        return symbols

    # ---- Mach-O ------------------------------------------------------------

    def _load_macho(self, binary: Any, path: Path) -> BinaryInfo:
        header = getattr(binary, "header", None)
        cpu = str(self._get_attr(header, "cpu_type", "") or "")
        arch, bitness = self._macho_arch(cpu)
        if bool(getattr(header, "is_64bit", False)):
            bitness = 64
        elif bool(getattr(header, "is_32bit", False)):
            bitness = 32
        magic_text = str(self._get_attr(header, "magic", "") or "").upper()
        endianness = "big" if "CIGAM" in magic_text else "little"
        image_base = self._as_int(getattr(binary, "imagebase", 0))
        entry_point = self._as_int(getattr(binary, "entrypoint", 0)) or None
        sections = [self._macho_section(s) for s in self._safe(binary, "sections")]
        imports = self._macho_imports(binary)
        exports = self._macho_exports(binary)
        symbols = self._macho_symbols(binary, sections)
        warnings: list[str] = []
        if not sections:
            warnings.append("Mach-O has no sections; section-based analysis is limited.")
        if not symbols and not exports:
            warnings.append(
                "No symbol table or exports found; function discovery is limited to the entry point."
            )
        return BinaryInfo(
            path=path,
            format="MachO",
            architecture=arch,
            bitness=bitness,
            endianness=endianness,
            entry_point=entry_point,
            image_base=image_base,
            sha256="",
            file_size=0,
            sections=sections,
            imports=imports,
            exports=exports,
            symbols=symbols,
            is_stripped=not symbols and not exports,
            warnings=warnings,
        )

    @staticmethod
    def _macho_arch(cpu: str) -> tuple[str, int]:
        upper = cpu.upper()
        if "X86_64" in upper:
            return "x86_64", 64
        if "ARM64" in upper or "ARM64E" in upper:
            return "aarch64", 64
        if "I386" in upper:
            return "x86", 32
        if "ARM" in upper:
            return "arm", 32
        if "POWERPC64" in upper:
            return "ppc64", 64
        if "POWERPC" in upper:
            return "ppc", 32
        return "unknown", 0

    @classmethod
    def _macho_section(cls, section: Any) -> SectionInfo:
        flags = cls._as_int(getattr(section, "flags", 0))
        offset = cls._as_int(getattr(section, "offset", 0))
        size = cls._as_int(getattr(section, "size", 0))
        virtual_address = cls._as_int(getattr(section, "virtual_address", 0))
        segment = None
        if bool(getattr(section, "has_segment", False)):
            try:
                segment = section.segment
            except Exception:
                segment = None
        init_protection = cls._as_int(getattr(segment, "init_protection", 0))
        entropy = getattr(section, "entropy", None)
        name = cls._decode_name(cls._get_attr(section, "fullname", "name"))
        return SectionInfo(
            name=name,
            virtual_address=virtual_address,
            size=size,
            offset=offset,
            # Sections without file bytes (S_ZEROFILL and friends) have offset 0.
            raw_size=size if offset > 0 else 0,
            entropy=float(entropy) if entropy is not None else None,
            # S_ATTR_PURE_INSTRUCTIONS / S_ATTR_SOME_INSTRUCTIONS.
            is_executable=bool(flags & 0x80000000) or bool(flags & 0x400),
            # Write permission lives on the segment; vm_prot_t VM_PROT_WRITE == 2.
            is_writable=bool(init_protection & 0x2),
            evidence=Evidence(
                source="macho.section_table",
                method="section_header",
                confidence=Confidence.CERTAIN,
                address=virtual_address,
                detail=f"Mach-O section {name!r}",
            ),
        )

    @classmethod
    def _macho_imports(cls, binary: Any) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        for symbol in cls._safe(binary, "imported_symbols"):
            name = cls._decode_name(getattr(symbol, "name", None))
            if not name:
                continue
            library_object = cls._get_attr(symbol, "library")
            library = cls._decode_name(cls._get_attr(library_object, "name")) if library_object is not None else ""
            value = cls._as_int(getattr(symbol, "value", 0))
            imports.append(
                ImportInfo(
                    name=name,
                    library=library or None,
                    address=value or None,
                    evidence=Evidence(
                        source="macho.undefined_symbols",
                        method="imported_symbol",
                        confidence=Confidence.HIGH,
                        address=value or None,
                        detail="undefined symbol bound by dyld at load time",
                    ),
                )
            )
        return imports

    @classmethod
    def _macho_exports(cls, binary: Any) -> list[ExportInfo]:
        exports: list[ExportInfo] = []
        for symbol in cls._safe(binary, "exported_symbols"):
            name = cls._decode_name(getattr(symbol, "name", None))
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            exports.append(
                ExportInfo(
                    name=name,
                    address=value or None,
                    evidence=Evidence(
                        source="macho.exported_symbols",
                        method="exported_symbol",
                        confidence=Confidence.HIGH if value else Confidence.MEDIUM,
                        address=value or None,
                        detail="symbol with dyld export information",
                    ),
                )
            )
        return exports

    @classmethod
    def _macho_symbols(cls, binary: Any, sections: list[SectionInfo]) -> list[SymbolInfo]:
        # Mach-O nlist entries do not encode function vs data. Membership in an
        # executable section is the strongest structural evidence available, so
        # it drives is_function and is stated explicitly in the evidence detail.
        exec_ranges = [
            (s.virtual_address, s.virtual_address + s.size)
            for s in sections
            if s.is_executable and s.size > 0
        ]
        symbols: list[SymbolInfo] = []
        seen: set[tuple[str, int]] = set()
        for symbol in cls._safe(binary, "symbols"):
            name = cls._decode_name(getattr(symbol, "name", None))
            if not name:
                continue
            value = cls._as_int(getattr(symbol, "value", 0))
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            size = cls._as_int(getattr(symbol, "size", 0))
            is_function = bool(value) and any(
                start <= value < end for start, end in exec_ranges
            )
            type_text = str(getattr(symbol, "type", "") or "")
            symbols.append(
                SymbolInfo(
                    name=name,
                    address=value,
                    size=size,
                    kind=type_text or "unknown",
                    is_function=is_function,
                    evidence=Evidence(
                        source="macho.symbol_table",
                        method="symtab_entry",
                        confidence=Confidence.HIGH,
                        address=value or None,
                        detail=(
                            "function inferred from executable-section membership"
                            if is_function
                            else "symbol kind is not encoded in the Mach-O symbol table"
                        ),
                    ),
                )
            )
        return symbols

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _decode_name(value: Any) -> str:
        """Decode a LIEF name that may arrive as bytes or str; strip padding."""
        if isinstance(value, (bytes, bytearray)):
            text = bytes(value).decode("utf-8", "replace")
        else:
            text = str(value or "")
        return text.split("\x00", 1)[0].strip()

    @staticmethod
    def _get_attr(obj: Any, *names: str, default: Any = None) -> Any:
        for name in names:
            if obj is not None and hasattr(obj, name):
                return getattr(obj, name)
        return default

    @staticmethod
    def _as_int(value: Any) -> int:
        if value is None:
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe(binary: Any, attribute: str) -> list[Any]:
        try:
            value = getattr(binary, attribute)
        except Exception:
            return []
        if value is None:
            return []
        try:
            return list(value)
        except TypeError:
            return []




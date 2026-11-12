"""Binary loading and metadata extraction backed by LIEF.

The loader normalizes PE, ELF, and Mach-O binaries into :class:`BinaryInfo`.
All addresses exposed by ``BinaryInfo`` are absolute virtual addresses (VA);
PE RVAs are rebased with the image base so downstream modules can treat every
format uniformly.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field, replace
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


# ---- fat (universal) Mach-O container --------------------------------------

# A universal binary wraps several thin Mach-O images behind one of these
# magics. The 8-byte header (magic + nfat_arch) is always followed by one
# ``fat_arch`` entry per slice; the "_64" variants use 64-bit offset/size
# fields and the "CIGAM" variants store the fields in little-endian order.
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

# magic -> (magic name, 64-bit table entries, struct byte order)
_FAT_MAGICS: dict[int, tuple[str, bool, str]] = {
    FAT_MAGIC: ("FAT_MAGIC", False, ">"),
    FAT_CIGAM: ("FAT_CIGAM", False, "<"),
    FAT_MAGIC_64: ("FAT_MAGIC_64", True, ">"),
    FAT_CIGAM_64: ("FAT_CIGAM_64", True, "<"),
}

_FAT_HEADER_SIZE = 8
_FAT_ARCH_SIZE = 20  # fat_arch: cputype, cpusubtype, offset, size, align
_FAT_ARCH_64_SIZE = 32  # fat_arch_64: 64-bit offset/size plus a reserved field

# Universal binaries in the wild carry at most a handful of slices (2-4 is
# typical). ``nfat_arch`` is attacker-controlled, so the table is hard-capped:
# without this bound a crafted 512 MiB file could declare hundreds of thousands
# of entries and burn seconds of parsing time plus proportional memory.
MAX_FAT_SLICES = 32

# ``fat_arch.align`` is an exponent (``1 << align``), never larger than 2**20
# in real toolchain output. Anything above that would let a file demand absurd
# slice alignment, so it is rejected rather than fed into ``1 << align``.
MAX_FAT_ALIGN = 20

# CPU_ARCH_ABI64 marks the 64-bit dialect of a CPU family (x86_64, arm64, ...).
_CPU_ARCH_ABI64 = 0x01000000
_CPU_TYPE_NAMES = {
    0x00000007: "x86",
    0x01000007: "x86_64",
    0x0000000C: "arm",
    0x0100000C: "aarch64",
    0x0200000C: "aarch64_32",
    0x00000012: "ppc",
    0x01000012: "ppc64",
}


def _cpu_type_name(cputype: int) -> str:
    """Stable, human-readable name for a Mach-O ``cputype``."""
    return _CPU_TYPE_NAMES.get(cputype, f"cputype_{cputype:#x}")


# LIEF ``CPU_TYPE`` member name -> numeric cputype, used only when the enum
# cannot be cast to ``int`` (older/limited LIEF builds).
_CPU_TYPE_ALIASES = {
    "I386": 0x00000007,
    "X86": 0x00000007,
    "X86_64": 0x01000007,
    "AMD64": 0x01000007,
    "ARM": 0x0000000C,
    "AARCH64": 0x0100000C,
    "ARM64": 0x0100000C,
    "ARM64E": 0x0100000C,
    "ARM64_32": 0x0200000C,
    "POWERPC": 0x00000012,
    "POWERPC64": 0x01000012,
}


# Selection rule tokens, kept stable for reports and tests.
RULE_PREFER_64BIT = "prefer_64bit"
RULE_FIRST_BY_OFFSET = "first_by_offset"


@dataclass(frozen=True)
class FatArch:
    """One ``fat_arch`` entry of a fat Mach-O architecture table."""

    index: int
    cputype: int
    cpusubtype: int
    offset: int
    size: int
    align: int

    @property
    def is_64bit(self) -> bool:
        return bool(self.cputype & _CPU_ARCH_ABI64)

    @property
    def arch_name(self) -> str:
        return _cpu_type_name(self.cputype)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "arch": self.arch_name,
            "cputype": f"0x{self.cputype:x}",
            "cpusubtype": self.cpusubtype,
            "offset": f"0x{self.offset:x}",
            "size": self.size,
            "align": self.align,
            "is_64bit": self.is_64bit,
        }


@dataclass(frozen=True)
class FatContainer:
    """A parsed fat (universal) Mach-O container plus the selected slice."""

    magic: int
    wide_entries: bool
    arches: tuple[FatArch, ...]
    slice: FatArch
    rule: str
    reason: str

    @property
    def magic_name(self) -> str:
        return _FAT_MAGICS[self.magic][0]

    @property
    def slice_count(self) -> int:
        return len(self.arches)

    def evidence_extra(self) -> dict[str, Any]:
        """Structured container metadata for :attr:`BinaryInfo.evidence`."""
        return {
            "fat": True,
            "fat_magic": f"0x{self.magic:08x}",
            "fat_magic_name": self.magic_name,
            "fat_arch_64": self.wide_entries,
            "slice_index": self.slice.index,
            "slice_count": self.slice_count,
            "slice_arch": self.slice.arch_name,
            "slice_cputype": f"0x{self.slice.cputype:x}",
            "slice_offset": self.slice.offset,
            "slice_size": self.slice.size,
            "selection_rule": self.rule,
            "selection_reason": self.reason,
            "available_arches": [arch.arch_name for arch in self.arches],
            # The table is already bounded by MAX_FAT_SLICES, but the evidence
            # list is capped explicitly so reports stay bounded by construction
            # even if that limit is ever raised.
            "available_slices": [
                arch.to_dict() for arch in self.arches[:MAX_FAT_SLICES]
            ],
        }


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
    # Container-level provenance (currently the fat Mach-O slice selection).
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
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
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data

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
    """Loads PE, ELF, Mach-O, and DEX binaries and extracts structural metadata."""

    MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 MiB safety guard

    def load(self, path: str | Path) -> BinaryInfo:
        """Load ``path`` and return normalized :class:`BinaryInfo`."""
        file_path = Path(path)
        self._validate(file_path)
        raw = file_path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()

        # DEX is a bytecode container, not an executable image: LIEF only
        # reaches it through the dedicated DEX parser, and the generic
        # ``lief.parse`` answers None for it. The magic cannot collide with
        # any fat/thin image magic, so checking it first is safe.
        if raw[:4] == b"dex\n":
            info = self._load_dex(file_path, raw)
            info.sha256 = sha256
            info.file_size = len(raw)
            return info

        # A fat (universal) container must be unwrapped before any of the thin
        # parsers run: LIEF would only ever see the container magic.
        container = self._fat_container(raw, file_path)
        fat_offset = 0
        if container is not None:
            chosen = container.slice
            payload = raw[chosen.offset : chosen.offset + chosen.size]
            fat_offset = chosen.offset
            try:
                binary = lief.parse(payload)
            except Exception as exc:  # LIEF raises several native error types
                raise BinaryLoadError(
                    f"Fat Mach-O {file_path}: slice {chosen.index} "
                    f"({chosen.arch_name}) could not be parsed: {exc}"
                ) from exc
            if binary is None:
                raise BinaryLoadError(
                    f"Fat Mach-O {file_path}: slice {chosen.index} "
                    f"({chosen.arch_name}) at offset 0x{chosen.offset:x} "
                    f"is not a valid thin Mach-O image"
                )
        else:
            try:
                binary = lief.parse(str(file_path))
            except Exception as exc:  # LIEF raises several native error types
                raise BinaryLoadError(f"LIEF could not parse {file_path}: {exc}") from exc
            if binary is None:
                raise BinaryLoadError(f"Unsupported or unreadable binary: {file_path}")

        fmt = self._format_name(binary)
        if container is not None:
            # Everything inside a fat container must be a thin Mach-O image:
            # an ELF or PE payload would be parsed with slice-relative offsets
            # and silently reported as that foreign format.
            if fmt != "MachO":
                raise BinaryLoadError(
                    f"Fat Mach-O {file_path}: fat slice is not a Mach-O image: {fmt}"
                )
            # With the payload parsed, the slice header is the authority on what
            # was actually loaded; the container table is only a claim.
            container = self._verify_fat_slice(container, binary, file_path)
        if fmt == "PE":
            info = self._load_pe(binary, file_path)
        elif fmt == "ELF":
            info = self._load_elf(binary, file_path)
        elif fmt == "MachO":
            info = self._load_macho(
                binary, file_path, fat_offset=fat_offset, container=container
            )
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

    # ---- fat (universal) Mach-O container ----------------------------------

    @classmethod
    def _fat_container(cls, raw: bytes, path: Path) -> FatContainer | None:
        """Parse a fat Mach-O container header and pick one slice.

        Returns ``None`` when ``raw`` does not start with a fat magic, so thin
        Mach-O, ELF and PE inputs keep taking the unchanged path. Malformed
        containers raise :class:`BinaryLoadError` naming the offending field.
        """
        if len(raw) < len(b"\xca\xfe\xba\xbe"):
            return None
        magic = int.from_bytes(raw[:4], "big")
        if magic not in _FAT_MAGICS:
            return None
        magic_name, wide_entries, order = _FAT_MAGICS[magic]
        entry_size = _FAT_ARCH_64_SIZE if wide_entries else _FAT_ARCH_SIZE

        if len(raw) < _FAT_HEADER_SIZE:
            raise BinaryLoadError(
                f"Malformed fat Mach-O {path}: nfat_arch field is truncated "
                f"({magic_name} header needs {_FAT_HEADER_SIZE} bytes, "
                f"file has {len(raw)})"
            )
        slice_count = struct.unpack_from(f"{order}I", raw, 4)[0]
        if slice_count == 0:
            raise BinaryLoadError(
                f"Malformed fat Mach-O {path}: nfat_arch is zero, a fat "
                f"{magic_name} container must hold at least one slice"
            )
        if slice_count > MAX_FAT_SLICES:
            raise BinaryLoadError(
                f"Malformed fat Mach-O {path}: nfat_arch={slice_count} exceeds "
                f"the supported maximum of {MAX_FAT_SLICES} slices"
            )

        table_end = _FAT_HEADER_SIZE + slice_count * entry_size
        if table_end > len(raw):
            raise BinaryLoadError(
                f"Malformed fat Mach-O {path}: fat_arch table truncated "
                f"(nfat_arch={slice_count} needs {table_end} bytes, "
                f"file has {len(raw)})"
            )

        format_string = f"{order}IIQQII" if wide_entries else f"{order}IIIII"
        arches: list[FatArch] = []
        for index in range(slice_count):
            base = _FAT_HEADER_SIZE + index * entry_size
            if wide_entries:
                # fat_arch_64 carries a trailing reserved u32.
                cputype, cpusubtype, offset, size, align = struct.unpack_from(
                    format_string, raw, base
                )[:5]
            else:
                cputype, cpusubtype, offset, size, align = struct.unpack_from(
                    format_string, raw, base
                )
            if size == 0:
                raise BinaryLoadError(
                    f"Malformed fat Mach-O {path}: fat_arch[{index}].size is zero"
                )
            if align > MAX_FAT_ALIGN:
                raise BinaryLoadError(
                    f"Malformed fat Mach-O {path}: fat_arch[{index}].align is "
                    f"{align}, above the supported maximum of {MAX_FAT_ALIGN}"
                )
            alignment = 1 << align
            if offset % alignment != 0:
                raise BinaryLoadError(
                    f"Malformed fat Mach-O {path}: fat_arch[{index}].offset "
                    f"0x{offset:x} is not aligned to {alignment} bytes "
                    f"(align={align})"
                )
            if offset < table_end:
                raise BinaryLoadError(
                    f"Malformed fat Mach-O {path}: fat_arch[{index}].offset "
                    f"0x{offset:x} points inside the fat header/table, which "
                    f"ends at 0x{table_end:x}"
                )
            if offset + size > len(raw):
                raise BinaryLoadError(
                    f"Malformed fat Mach-O {path}: fat_arch[{index}].offset/size "
                    f"outside the file (offset=0x{offset:x}, size=0x{size:x}, "
                    f"file size=0x{len(raw):x})"
                )
            arches.append(
                FatArch(
                    index=index,
                    cputype=cputype,
                    cpusubtype=cpusubtype,
                    offset=offset,
                    size=size,
                    align=align,
                )
            )

        chosen, rule, reason = cls._select_fat_slice(arches)
        return FatContainer(
            magic=magic,
            wide_entries=wide_entries,
            arches=tuple(arches),
            slice=chosen,
            rule=rule,
            reason=reason,
        )

    @staticmethod
    def _select_fat_slice(arches: list[FatArch]) -> tuple[FatArch, str, str]:
        """Pick one slice deterministically: 64-bit first, then lowest offset."""
        wide = [arch for arch in arches if arch.is_64bit]
        candidates = wide or arches
        chosen = min(candidates, key=lambda arch: (arch.offset, arch.index))
        if wide:
            return (
                chosen,
                RULE_PREFER_64BIT,
                "64-bit slice preferred over 32-bit slices, lowest file offset wins",
            )
        return (
            chosen,
            RULE_FIRST_BY_OFFSET,
            "no 64-bit slice present, first slice by file offset wins",
        )

    @classmethod
    def _verify_fat_slice(
        cls, container: FatContainer, binary: Any, path: Path
    ) -> FatContainer:
        """Reconcile the container entry with the parsed thin Mach-O header.

        The table entry only claims an architecture; the slice header proves it.
        A mismatch means the bytes are not what the container advertises, so it
        is rejected. On success the container's slice is rebuilt from the real
        header, keeping ``slice_cputype``/``slice_arch`` evidence honest.
        """
        header_cputype = cls._macho_header_cputype(binary)
        if header_cputype is None:  # LIEF build without a usable cpu_type
            return container
        chosen = container.slice
        if header_cputype != chosen.cputype:
            raise BinaryLoadError(
                f"Fat Mach-O {path}: fat_arch[{chosen.index}].cputype "
                f"{_cpu_type_name(chosen.cputype)} (0x{chosen.cputype:x}) does "
                f"not match the parsed slice header cpu_type "
                f"{_cpu_type_name(header_cputype)} (0x{header_cputype:x})"
            )
        return replace(container, slice=replace(chosen, cputype=header_cputype))

    @staticmethod
    def _macho_header_cputype(binary: Any) -> int | None:
        """Numeric ``cputype`` of a parsed Mach-O header, or ``None``."""
        header = getattr(binary, "header", None)
        cpu_type = getattr(header, "cpu_type", None)
        if cpu_type is None:
            return None
        try:
            return int(cpu_type)
        except (TypeError, ValueError):
            pass
        # LIEF builds that expose only the enum member name.
        name = str(getattr(cpu_type, "name", cpu_type) or "").upper()
        return _CPU_TYPE_ALIASES.get(name)

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

    def _load_macho(
        self,
        binary: Any,
        path: Path,
        *,
        fat_offset: int = 0,
        container: FatContainer | None = None,
    ) -> BinaryInfo:
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
        # Section offsets from LIEF are relative to the parsed slice; shift them
        # so they stay valid offsets into the outer fat container.
        sections = [
            self._macho_section(s, fat_offset) for s in self._safe(binary, "sections")
        ]
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
        evidence = None
        if container is not None:
            chosen = container.slice
            evidence = Evidence(
                source="macho.fat_header",
                method="fat_arch_table",
                confidence=Confidence.CERTAIN,
                detail=(
                    f"selected slice {chosen.index} of {container.slice_count} "
                    f"({chosen.arch_name}) from a {container.magic_name} container: "
                    f"{container.reason}"
                ),
                extra=container.evidence_extra(),
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
            evidence=evidence,
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
    def _macho_section(cls, section: Any, fat_offset: int = 0) -> SectionInfo:
        flags = cls._as_int(getattr(section, "flags", 0))
        offset = cls._as_int(getattr(section, "offset", 0))
        size = cls._as_int(getattr(section, "size", 0))
        virtual_address = cls._as_int(getattr(section, "virtual_address", 0))
        # A slice-relative offset of 0 means "no file bytes" (S_ZEROFILL and
        # friends); those stay unmapped even inside a fat container.
        file_offset = offset + fat_offset if offset > 0 else offset
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
            offset=file_offset,
            # Sections without file bytes (S_ZEROFILL and friends) have offset 0.
            raw_size=size if file_offset > 0 else 0,
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

    # ---- DEX ---------------------------------------------------------------

    @staticmethod
    def _load_dex(path: Path, raw: bytes) -> BinaryInfo:
        """Normalize a DEX bytecode container into :class:`BinaryInfo`.

        DEX has no virtual address space and no sections: method addresses are
        **file offsets**, stated in a loader warning and in every method's
        evidence. Defined methods (with bytecode) become function symbols;
        referenced-but-undefined methods (external APIs like ``println``)
        become imports with the defining class as their ``library``.
        """
        try:
            dex = lief.DEX.parse(str(path))
        except Exception as exc:
            raise BinaryLoadError(f"LIEF could not parse DEX {path}: {exc}") from exc
        if dex is None:
            raise BinaryLoadError(f"Unsupported or unreadable DEX: {path}")

        # The endianness lives in the header's endian_tag at offset 0x28
        # (0x12345678 = little-endian, byte-swapped = big-endian).
        endian_tag = int.from_bytes(raw[0x28:0x2C], "little")
        endianness = "big" if endian_tag == 0x78563412 else "little"

        warnings: list[str] = [
            "DEX container: no virtual address space; symbol addresses are file offsets",
            "Dalvik bytecode disassembly is not supported yet",
        ]

        symbols: list[SymbolInfo] = []
        imports: list[ImportInfo] = []
        for method in dex.methods:
            class_name = ""
            if method.has_class and method.cls is not None:
                class_name = str(method.cls.fullname)
            qualified = f"{class_name}->{method.name}" if class_name else str(method.name)
            code_offset = int(getattr(method, "code_offset", 0) or 0)
            if code_offset > 0:
                symbols.append(
                    SymbolInfo(
                        name=qualified,
                        address=code_offset,
                        kind="method",
                        is_function=True,
                        evidence=Evidence(
                            source="dex.method_ids",
                            method="class_data",
                            confidence=Confidence.HIGH,
                            address=code_offset,
                            detail=(
                                f"{qualified}: code at file offset 0x{code_offset:x} "
                                "(DEX addresses are file offsets, not VA)"
                            ),
                        ),
                    )
                )
            else:
                imports.append(
                    ImportInfo(
                        name=qualified,
                        library=class_name or None,
                        evidence=Evidence(
                            source="dex.method_ids",
                            method="method_reference",
                            confidence=Confidence.HIGH,
                            detail=(
                                f"{qualified}: referenced but not defined in this container"
                            ),
                        ),
                    )
                )

        return BinaryInfo(
            path=path,
            format="DEX",
            architecture="dalvik",
            bitness=0,
            endianness=endianness,
            entry_point=None,
            image_base=0,
            sha256="",
            file_size=0,
            sections=[],
            imports=imports,
            exports=[],
            symbols=symbols,
            is_stripped=not symbols,
            warnings=warnings,
        )

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




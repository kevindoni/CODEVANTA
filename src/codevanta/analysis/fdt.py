"""Flattened devicetree (FDT/DTB) parser: pure Python, bounded, typed.

Reads the big-endian header (magic ``0xd00dfeed``), the memory reservation
block, and does one *shallow* walk of the structure block: the root node,
the top-level node names, and the properties of one chosen node (the root by
default, or ``--node NAME``). Property values are truncated to
:data:`MAX_VALUE_BYTES`; everything else is summarised away with warnings.
Strings-block lookups stay inside the declared strings block.

Malformed blobs -- bad magic, truncated header, out-of-range offsets, broken
token streams, missing ``FDT_END``, unknown tokens, string offsets outside
the strings block -- raise the typed
:class:`~codevanta.core.report.AnalysisError`, never ``struct``'s bare
exceptions. Legacy FDT versions (< 16) are refused with a typed error; the
modern v16/v17 layout is what every mainline kernel ships.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "FDT_MAGIC",
    "MAX_FILE_BYTES",
    "MAX_NODES",
    "MAX_PROPS",
    "MAX_RESERVATIONS",
    "MAX_VALUE_BYTES",
    "SUPPORTED_LAST_COMP_VERSIONS",
    "DtbProperty",
    "DtbReservation",
    "DtbSummary",
    "parse_dtb",
    "parse_dtb_file",
]

#: ``fdt_magic`` from the devicetree specification.
FDT_MAGIC = 0xD00DFEED

#: Reservation entries kept; the spec has no cap, this lane does.
MAX_RESERVATIONS = 32

#: Properties kept for the chosen node (bounded work).
MAX_PROPS = 64

#: Top-level node names kept (bounded work).
MAX_NODES = 64

#: Property value bytes kept per property; the rest is truncated away.
MAX_VALUE_BYTES = 64

#: Hard ceiling on the blob file itself (devicetrees are small; house rule).
MAX_FILE_BYTES = 16 * 1024 * 1024

#: Compatibility levels this parser speaks (v16 layout, v17 adds size_dt_struct).
SUPPORTED_LAST_COMP_VERSIONS: tuple[int, ...] = (16, 17)

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "fdt.parse"

#: Structure-block tokens from the devicetree specification.
_TOK_BEGIN_NODE = 1
_TOK_END_NODE = 2
_TOK_PROP = 3
_TOK_NOP = 4
_TOK_END = 9

#: Ceiling on warnings kept per summary.
MAX_WARNINGS = 32


@dataclass(frozen=True)
class DtbReservation:
    """One memory-reservation entry: a physical range the OS must not touch."""

    address: int
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {"address": f"0x{self.address:x}", "size": f"0x{self.size:x}"}


@dataclass(frozen=True)
class DtbProperty:
    """One property of the chosen node, value truncated to a safe prefix."""

    name: str
    value: bytes
    truncated: bool
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "length": self.length or len(self.value)}
        data["kept_bytes"] = len(self.value)
        data["value_hex"] = self.value.hex()
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in self.value)
        data["value_ascii"] = printable
        if self.truncated:
            data["value_truncated"] = True
        return data


@dataclass(frozen=True)
class DtbSummary:
    """Bounded, evidence-backed summary of one flattened devicetree blob."""

    version: int = 0
    last_comp_version: int = 0
    boot_cpuid_phys: int = 0
    total_size: int = 0
    strings_size: int = 0
    struct_size: int = 0
    reservations: tuple[DtbReservation, ...] = ()
    nodes: tuple[str, ...] = ()
    chosen_node: str | None = None
    properties: tuple[DtbProperty, ...] = ()
    reservations_truncated: bool = False
    nodes_truncated: bool = False
    props_truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="structure_block_walk",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "last_comp_version": self.last_comp_version,
            "boot_cpuid_phys": self.boot_cpuid_phys,
            "total_size": self.total_size,
            "strings_size": self.strings_size,
            "struct_size": self.struct_size,
            "reservations": [item.to_dict() for item in self.reservations],
            "nodes": list(self.nodes),
            "chosen_node": self.chosen_node,
            "properties": [item.to_dict() for item in self.properties],
            "reservations_truncated": self.reservations_truncated,
            "nodes_truncated": self.nodes_truncated,
            "props_truncated": self.props_truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


def _check_header(data: bytes) -> dict[str, int]:
    """Parse and validate the 10-field big-endian FDT header."""
    if len(data) < 40:
        raise AnalysisError(
            f"blob is {len(data)} bytes; the FDT header alone needs 40 bytes"
        )
    fields = struct.unpack(">10I", data[:40])
    names = (
        "magic",
        "totalsize",
        "off_dt_struct",
        "off_dt_strings",
        "off_mem_rsvmap",
        "version",
        "last_comp_version",
        "boot_cpuid_phys",
        "size_dt_strings",
        "size_dt_struct",
    )
    header = dict(zip(names, fields, strict=True))
    if header["magic"] != FDT_MAGIC:
        raise AnalysisError(
            f"bad devicetree magic 0x{header['magic']:08x}; expected 0x{FDT_MAGIC:08x}"
        )
    if header["last_comp_version"] not in SUPPORTED_LAST_COMP_VERSIONS:
        raise AnalysisError(
            f"unsupported devicetree compatibility level "
            f"{header['last_comp_version']}; supported: "
            f"{SUPPORTED_LAST_COMP_VERSIONS} (modern v16/v17 blobs only)"
        )
    if header["last_comp_version"] > header["version"]:
        raise AnalysisError(
            f"header claims last_comp_version {header['last_comp_version']} above "
            f"its own version {header['version']}; the blob is malformed"
        )
    totalsize = header["totalsize"]
    if totalsize > len(data):
        raise AnalysisError(
            f"header totalsize {totalsize} exceeds the {len(data)} bytes on disk; "
            "the blob is truncated"
        )
    for key in ("off_dt_struct", "off_dt_strings", "off_mem_rsvmap"):
        if not 40 <= header[key] <= totalsize:
            raise AnalysisError(
                f"header offset {key}={header[key]} is outside the blob "
                f"(40 .. {totalsize})"
            )
    for key, offset in (
        ("size_dt_struct", "off_dt_struct"),
        ("size_dt_strings", "off_dt_strings"),
    ):
        if header[offset] + header[key] > totalsize:
            raise AnalysisError(
                f"header block {key}={header[key]} at offset {header[offset]} "
                f"runs past the blob totalsize {totalsize}"
            )
    if header["size_dt_struct"] == 0:
        raise AnalysisError("header declares an empty structure block")
    return header


def _read_reservations(data: bytes, start: int, limit: int) -> tuple[tuple[DtbReservation, ...], bool]:
    """Read ``(address, size)`` pairs until the ``(0, 0)`` terminator."""
    reservations: list[DtbReservation] = []
    truncated = False
    pos = start
    while pos + 16 <= limit:
        address, size = struct.unpack_from(">QQ", data, pos)
        pos += 16
        if address == 0 and size == 0:
            return tuple(reservations), truncated
        if len(reservations) >= MAX_RESERVATIONS:
            return tuple(reservations), True
        reservations.append(DtbReservation(address=address, size=size))
    raise AnalysisError(
        "memory reservation block has no (0, 0) terminator inside its region"
    )


def _string_at(data: bytes, strings_off: int, strings_size: int, nameoff: int) -> str:
    """Return the NUL-terminated string at ``nameoff`` in the strings block."""
    if nameoff >= strings_size:
        raise AnalysisError(
            f"property name offset {nameoff} is outside the strings block "
            f"({strings_size} bytes)"
        )
    start = strings_off + nameoff
    end = data.find(b"\x00", start, strings_off + strings_size)
    if end < 0:
        raise AnalysisError(
            f"property name at offset {nameoff} has no NUL terminator inside "
            "the strings block"
        )
    try:
        return data[start:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"property name at offset {nameoff} is not UTF-8: {exc}") from exc


def _walk_structure(
    data: bytes,
    header: dict[str, int],
    chosen: str,
) -> tuple[tuple[str, ...], tuple[DtbProperty, ...], bool, bool]:
    """Shallow walk of the structure block: top-level names + chosen props.

    Returns ``(nodes, properties, nodes_truncated, props_truncated)``. Depth
    accounting: the root node sits at depth 1, its children (the top-level
    nodes) at depth 2. ``current_top`` names the top-level node whose body is
    being walked (``""`` while inside the root itself). Only properties at
    depth 1 (root, when chosen is ``""``) or depth 2 (inside the chosen
    top-level node) are kept; deeper subtrees are stepped over token by
    token and their properties are never parsed.
    """
    struct_off = header["off_dt_struct"]
    struct_size = header["size_dt_struct"]
    strings_off = header["off_dt_strings"]
    strings_size = header["size_dt_strings"]
    end = struct_off + struct_size
    pos = struct_off
    depth = 0
    current_top = ""
    nodes: list[str] = []
    nodes_truncated = False
    props: list[DtbProperty] = []
    props_truncated = False
    seen_end = False
    while pos + 4 <= end:
        token = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        if token == _TOK_END:
            seen_end = True
            break
        if token == _TOK_NOP:
            continue
        if token == _TOK_BEGIN_NODE:
            name_end = data.find(b"\x00", pos, end)
            if name_end < 0:
                raise AnalysisError("node name has no NUL terminator inside the structure block")
            name = data[pos:name_end].decode("utf-8", errors="replace")
            pos = (name_end + 1 + 3) & ~3  # advance past the name, 4-byte aligned
            depth += 1
            if depth == 2:
                if len(nodes) >= MAX_NODES:
                    nodes_truncated = True
                else:
                    nodes.append(name)
                current_top = name
            continue
        if token == _TOK_END_NODE:
            depth -= 1
            if depth < 0:
                raise AnalysisError("structure block ends a node that never began")
            if depth == 1:
                current_top = ""  # back inside the root node
            continue
        if token == _TOK_PROP:
            if depth == 0:
                raise AnalysisError("structure block has a property outside any node")
            if pos + 8 > end:
                raise AnalysisError("structure block ends inside a property header")
            length, nameoff = struct.unpack_from(">II", data, pos)
            pos += 8
            if pos + length > end:
                raise AnalysisError("structure block ends inside a property value")
            wanted = (depth == 1 or depth == 2) and current_top == chosen
            if wanted:
                if len(props) >= MAX_PROPS:
                    props_truncated = True
                else:
                    value = bytes(data[pos : pos + length])
                    truncated = length > MAX_VALUE_BYTES
                    props.append(
                        DtbProperty(
                            name=_string_at(data, strings_off, strings_size, nameoff),
                            value=value[:MAX_VALUE_BYTES],
                            truncated=truncated,
                            length=length,
                        )
                    )
            pos = (pos + length + 3) & ~3  # property values are 4-byte aligned
            continue
        raise AnalysisError(f"unknown structure-block token 0x{token:08x} at offset {pos - 4}")
    if not seen_end:
        raise AnalysisError("structure block has no FDT_END token")
    if depth != 0:
        raise AnalysisError("structure block ends with unclosed node(s)")
    return tuple(nodes), tuple(props), nodes_truncated, props_truncated


def parse_dtb(data: bytes, *, node: str | None = None) -> DtbSummary:
    """Parse one flattened devicetree blob into a typed, bounded summary.

    ``node`` selects whose properties are kept: ``None`` (or ``""``) keeps
    the root's own properties; a name must match one top-level node exactly
    and is refused with a typed error listing what exists instead.
    """
    if isinstance(data, memoryview):
        data = data.tobytes()
    if not isinstance(data, (bytes, bytearray)):
        raise AnalysisError(
            f"dtb data must be bytes, got {type(data).__name__}"
        )
    data = bytes(data)
    if len(data) > MAX_FILE_BYTES:
        raise AnalysisError(
            f"blob is {len(data)} bytes; the ceiling for one devicetree is "
            f"{MAX_FILE_BYTES} bytes"
        )
    header = _check_header(data)
    reservations, reservations_truncated = _read_reservations(
        data, header["off_mem_rsvmap"], header["off_dt_struct"] + header["size_dt_struct"]
    )
    nodes, props, nodes_truncated, props_truncated = _walk_structure(
        data, header, node if node is not None else ""
    )
    chosen = node if node is not None else ""
    if node and node not in nodes:
        available = ", ".join(nodes[:8]) or "(none)"
        raise AnalysisError(
            f"node {node!r} is not a top-level node of this devicetree; "
            f"top-level: {available}"
        )
    warnings: list[str] = []
    if reservations_truncated:
        _note(warnings, f"reservation limit {MAX_RESERVATIONS} reached; further entries dropped")
    if nodes_truncated:
        _note(warnings, f"top-level node limit {MAX_NODES} reached; further nodes dropped")
    if props_truncated:
        _note(warnings, f"property limit {MAX_PROPS} reached; further properties dropped")
    chosen_label = chosen if chosen else "root"
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="structure_block_walk",
        confidence=Confidence.HIGH,
        detail=(
            f"v{header['version']} dtb, {len(nodes)} top-level node(s), "
            f"{len(props)} propert(y/ies) of {chosen_label}"
        ),
    )
    return DtbSummary(
        version=header["version"],
        last_comp_version=header["last_comp_version"],
        boot_cpuid_phys=header["boot_cpuid_phys"],
        total_size=header["totalsize"],
        strings_size=header["size_dt_strings"],
        struct_size=header["size_dt_struct"],
        reservations=reservations,
        nodes=nodes,
        chosen_node=chosen_label,
        properties=props,
        reservations_truncated=reservations_truncated,
        nodes_truncated=nodes_truncated,
        props_truncated=props_truncated,
        warnings=warnings,
        evidence=evidence,
    )


def parse_dtb_file(path: str | Path, *, node: str | None = None) -> DtbSummary:
    """Read one ``.dtb`` file from disk and parse it."""
    if not isinstance(path, (str, Path)):
        raise AnalysisError(f"path must be a str or Path, got {type(path).__name__}")
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"devicetree file not found: {target}")
    return parse_dtb(target.read_bytes(), node=node)




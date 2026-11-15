"""PE visual-asset extractor (lane-assets): icons, bitmaps, cursors as PNG.

Extracts the *real* visual assets a UI clone needs: ``RT_GROUP_ICON``/
``RT_ICON``, ``RT_GROUP_CURSOR``/``RT_CURSOR`` and ``RT_BITMAP`` resources
inside the PE resource directory are device-independent bitmaps (DIBs); this
module decodes them into RGBA rows and writes deterministic PNG artifacts
(``<group>_<id>_<w>x<h>.png``) plus a manifest (dimensions, bit depth, cursor
hotspots, sizes, sha256).

The resource-directory walk is reused verbatim from
:mod:`codevanta.analysis.pe_resources` (header parser, section mapping,
bounded walker) plus the leaf fetcher from :mod:
`codevanta.analysis.winres_ui` -- the same seam that module uses; this module
only decodes the GRPICONDIR/GRPICONDIRENTRY group headers and the DIB
payloads. PNG encoding is the minimal deterministic encoder from :mod:
`codevanta.analysis.win_gui` (fixed zlib level, filter type 0), so identical
pixels give byte-identical files and a re-run over the same input reproduces
the same manifest.

Bounds (128 assets, 32 entries per group) are reported through
``assets_truncated`` and warnings instead of unbounded work. Unsupported DIB
variants (compression other than BI_RGB/BI_BITFIELDS, depths outside
1/4/8/16/24/32, truncated payloads) are skipped with a warning -- never a
crash. A PE without image resources is a valid, empty manifest; a missing or
unreadable file is the typed :class:`~codevanta.core.report.AnalysisError`.
Everything is pure ``struct`` + ``bytes`` -- nothing is executed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.analysis.containers import MAX_FILE_BYTES
from codevanta.analysis.pe_resources import (
    MAX_DIRECTORIES,
    _Leaf,
    _parse_pe_image,
    _rva_to_offset,
    _walk_directory,
)
from codevanta.analysis.win_gui import encode_png
from codevanta.analysis.winres_ui import _fetch_blob
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_ASSETS",
    "MAX_GROUP_ENTRIES",
    "AssetManifest",
    "extract_visual_assets",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "pe.assets"

#: Assets (PNG files) extracted per call (bounded work).
MAX_ASSETS = 128

#: Entries decoded inside one group header (bounded work).
MAX_GROUP_ENTRIES = 32

#: Resource types this lane decodes (winuser.h ids).
RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3
RT_GROUP_CURSOR = 12
RT_GROUP_ICON = 14

#: Deterministic manifest order across kinds.
_KIND_ORDER = {"icon": 0, "cursor": 1, "bitmap": 2}

#: Sanity ceiling on one decoded dimension; anything larger is hostile input
#: (real icons/cursors are <= 256 px, but the DIB header is attacker-controlled).
_MAX_DIM = 4096


# ---- group header (GRPICONDIR + GRPICONDIRENTRY) --------------------------------


@dataclass(frozen=True)
class _GroupEntry:
    """One GRPICONDIRENTRY: nominal size plus the id of its image blob.

    For cursor groups ``planes``/``bit_count`` carry the hotspot (x, y)
    instead of plane/bit counts -- recorded as ``hotspot`` in the manifest.
    """

    width: int  # 0 on disk means 256
    height: int
    color_count: int
    planes: int  # hotspot x for cursor groups
    bit_count: int  # hotspot y for cursor groups
    resource_id: int


def _parse_group_blob(
    blob: bytes, label: str, warnings: list[str]
) -> list[_GroupEntry]:
    """Parse one ``GRPICONDIR`` + entries (bounded, warning-and-skip on errors)."""
    if len(blob) < 6:
        warnings.append(f"{label}: group directory truncated ({len(blob)} bytes); skipped")
        return []
    reserved, group_type, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0:
        warnings.append(f"{label}: reserved field is {reserved} (expected 0); decoded anyway")
    if group_type not in (1, 2):
        warnings.append(f"{label}: unknown group type {group_type} (want 1 icon / 2 cursor)")
        return []
    kept = min(count, MAX_GROUP_ENTRIES)
    if count > MAX_GROUP_ENTRIES:
        warnings.append(f"{label}: {count} entries bounded at {MAX_GROUP_ENTRIES}")
    entries: list[_GroupEntry] = []
    for index in range(kept):
        off = 6 + 14 * index
        if off + 14 > len(blob):
            warnings.append(f"{label}: entry {index} truncated; skipped")
            break
        (
            width_byte, height_byte, color_count, _res, planes, bit_count, _bytes, rid,
        ) = struct.unpack_from("<BBBBHHIH", blob, off)
        entries.append(
            _GroupEntry(
                width=256 if width_byte == 0 else width_byte,
                height=256 if height_byte == 0 else height_byte,
                color_count=color_count,
                planes=planes,
                bit_count=bit_count,
                resource_id=rid,
            )
        )
    return entries



# ---- DIB decoding ---------------------------------------------------------------


def _scale5(value: int) -> int:
    """5-bit channel -> 8-bit via bit replication (0x1F -> 0xFF exactly)."""
    return (value << 3) | (value >> 2)


def _decode_dib(
    blob: bytes,
    *,
    double_height: bool,
    label: str,
    warnings: list[str],
) -> tuple[list[list[list[int]]], int, int, int] | None:
    """Decode one DIB payload into RGBA rows (top-down) or ``None`` on skip.

    ``double_height`` selects icon/cursor payloads, whose ``biHeight`` counts
    the pixel rows *plus* the 1bpp AND-mask rows (pixel height = biHeight // 2).
    ``RT_BITMAP`` payloads carry the real height and no AND mask. Every skip
    path appends a warning naming the resource -- never raises, never crashes.
    """
    if len(blob) < 40:
        warnings.append(f"{label}: DIB header truncated ({len(blob)} bytes); skipped")
        return None
    bi_size = struct.unpack_from("<I", blob, 0)[0]
    if bi_size < 40 or bi_size > len(blob):
        warnings.append(f"{label}: malformed DIB (biSize={bi_size}); skipped")
        return None
    bi_width, bi_height = struct.unpack_from("<ii", blob, 4)
    _planes, bi_bitcount = struct.unpack_from("<HH", blob, 12)
    bi_compression = struct.unpack_from("<I", blob, 16)[0]
    bi_clr_used = struct.unpack_from("<I", blob, 32)[0]

    if bi_compression not in (0, 3):
        warnings.append(f"{label}: unsupported DIB compression {bi_compression}; skipped")
        return None
    if bi_bitcount not in (1, 4, 8, 16, 24, 32):
        warnings.append(f"{label}: unsupported DIB bit depth {bi_bitcount}; skipped")
        return None
    if bi_compression == 3 and bi_bitcount != 32:
        warnings.append(f"{label}: BI_BITFIELDS only decoded at 32bpp; skipped")
        return None
    if bi_width <= 0 or bi_width > _MAX_DIM:
        warnings.append(f"{label}: unsupported DIB width {bi_width}; skipped")
        return None
    if bi_height <= 0:
        warnings.append(
            f"{label}: unsupported DIB height {bi_height} (top-down rows are not decoded); skipped"
        )
        return None
    if double_height and bi_height % 2:
        warnings.append(f"{label}: odd icon DIB height {bi_height}; skipped")
        return None
    pixel_height = bi_height // 2 if double_height else bi_height
    mask_rows = pixel_height if double_height else 0
    if pixel_height <= 0 or pixel_height > _MAX_DIM:
        warnings.append(f"{label}: unsupported DIB pixel height {pixel_height}; skipped")
        return None

    # BI_BITFIELDS carries three color-mask DWORDs right after the header; it
    # only appears at 32bpp here, where the masks are honored as plain BGRA.
    masks_span = 12 if bi_compression == 3 else 0
    palette_off = bi_size + masks_span
    palette: list[tuple[int, int, int]] = []
    if bi_bitcount <= 8:
        count = bi_clr_used if bi_clr_used else 1 << bi_bitcount
        if palette_off + 4 * count > len(blob):
            warnings.append(f"{label}: palette truncated ({count} entries claimed); skipped")
            return None
        for index in range(count):
            b, g, r = blob[palette_off + 4 * index : palette_off + 4 * index + 3]
            palette.append((r, g, b))
    pixel_off = palette_off + (4 * len(palette) if palette else 0)
    row_stride = ((bi_width * bi_bitcount + 31) // 32) * 4
    mask_stride = ((bi_width + 31) // 32) * 4
    pixels_bytes = row_stride * pixel_height  # pixel rows only; mask rows use mask_stride
    mask_bytes = mask_stride * mask_rows
    if pixel_off + pixels_bytes + mask_bytes > len(blob):
        warnings.append(
            f"{label}: DIB payload truncated ({max(len(blob) - pixel_off, 0)} of "
            f"{pixels_bytes + mask_bytes} pixel/mask bytes claimed); skipped"
        )
        return None
    mask_base = pixel_off + pixels_bytes


    def mask_bit(x: int, dib_row: int) -> bool:
        """One 1bpp AND-mask bit (MSB-first within the 4-byte-aligned row)."""
        byte = blob[mask_base + mask_stride * dib_row + (x >> 3)]
        return bool((byte >> (7 - (x & 7))) & 1)

    rows: list[list[list[int]]] = []
    for y in range(pixel_height):
        dib_row = pixel_height - 1 - y  # bottom-up storage -> top-down output
        base = pixel_off + row_stride * dib_row
        row: list[list[int]] = []
        for x in range(bi_width):
            if bi_bitcount == 32:
                b, g, r, a = blob[base + 4 * x : base + 4 * x + 4]
                row.append([r, g, b, a])
            elif bi_bitcount == 24:
                b, g, r = blob[base + 3 * x : base + 3 * x + 3]
                row.append([r, g, b, 255])
            elif bi_bitcount == 16:
                value = struct.unpack_from("<H", blob, base + 2 * x)[0]
                row.append(
                    [
                        _scale5((value >> 10) & 0x1F),
                        _scale5((value >> 5) & 0x1F),
                        _scale5(value & 0x1F),
                        255,
                    ]
                )
            else:
                if bi_bitcount == 8:
                    index = blob[base + x]
                elif bi_bitcount == 4:
                    byte = blob[base + (x >> 1)]
                    index = (byte >> 4) if x % 2 == 0 else (byte & 0xF)
                else:
                    byte = blob[base + (x >> 3)]
                    index = (byte >> (7 - (x & 7))) & 1
                if index >= len(palette):
                    warnings.append(
                        f"{label}: palette index {index} out of range at row {y}; skipped"
                    )
                    return None
                r, g, b = palette[index]
                row.append([r, g, b, 255])
        rows.append(row)

    # Alpha discipline: 32bpp honors the stored alpha byte; when *every* alpha
    # byte is 0 (alpha-blind encoders) and an AND mask exists, the mask decides.
    # Depths <= 8bpp and 16bpp have no alpha channel: the mask decides outright.
    # 24bpp stays fully opaque by definition.
    if mask_rows:
        if bi_bitcount == 32:
            all_zero = all(pixel[3] == 0 for row in rows for pixel in row)
            if all_zero:
                for y, row in enumerate(rows):
                    dib_row = pixel_height - 1 - y
                    for x, pixel in enumerate(row):
                        pixel[3] = 0 if mask_bit(x, dib_row) else 255
        elif bi_bitcount in (1, 4, 8, 16):
            for y, row in enumerate(rows):
                dib_row = pixel_height - 1 - y
                for x, pixel in enumerate(row):
                    if mask_bit(x, dib_row):
                        pixel[3] = 0
    return rows, bi_width, pixel_height, bi_bitcount



# ---- naming ---------------------------------------------------------------------


def _sanitize_component(raw: str) -> str:
    """Make one path component safe: ASCII [A-Za-z0-9._-] only, bounded.

    Kills traversal (``/`` and ``\\`` collapse to ``_``, leading/trailing dots
    are stripped so ``..`` cannot survive) while keeping names readable.
    """
    cleaned = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_" for char in raw
    )
    cleaned = cleaned.strip(".").strip()[:64]
    return cleaned or "res"


def _unique_name(
    out_dir: Path, group: str, rid: int, w: int, h: int, used: set[str]
) -> Path:
    """Deterministic collision-free ``<group>_<rid>_<w>x<h>.png`` path."""
    name = f"{group}_{rid}_{w}x{h}.png"
    if name in used:
        suffix = 2
        while f"{group}_{rid}_{w}x{h}_{suffix}.png" in used:
            suffix += 1
        name = f"{group}_{rid}_{w}x{h}_{suffix}.png"
    used.add(name)
    return out_dir / name


def _int_or_none(raw: str) -> int | None:
    """Parse an integer resource name (string names yield ``None``)."""
    try:
        return int(raw)
    except ValueError:
        return None


# ---- summary + public API -------------------------------------------------------


@dataclass(frozen=True)
class AssetManifest:
    """Bounded, JSON-safe view of one PE's visual assets (PNG artifacts)."""

    path: str
    output_directory: str
    resource_table_present: bool
    asset_count: int
    counts: dict[str, int]
    assets: tuple[dict[str, Any], ...]
    assets_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "output_directory": self.output_directory,
            "resource_table_present": self.resource_table_present,
            "asset_count": self.asset_count,
            "counts": dict(self.counts),
            "assets": [dict(asset) for asset in self.assets],
            "assets_truncated": self.assets_truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _manifest(
    target: Path,
    out_dir: Path,
    assets: list[dict[str, Any]],
    warnings: list[str],
    *,
    truncated: bool,
    present: bool,
    root_rva: int | None,
    leaf_count: int,
) -> AssetManifest:
    """Freeze one manifest with the lane's HIGH-confidence evidence record."""
    counts = {
        "icon": sum(1 for asset in assets if asset["kind"] == "icon"),
        "cursor": sum(1 for asset in assets if asset["kind"] == "cursor"),
        "bitmap": sum(1 for asset in assets if asset["kind"] == "bitmap"),
    }
    detail = (
        f"{len(assets)} asset(s): {counts['icon']} icon, {counts['cursor']} cursor, "
        f"{counts['bitmap']} bitmap, decoded from PE DIBs and written as PNG"
        if assets
        else "no RT_ICON/RT_BITMAP/RT_CURSOR resources present; no assets extracted"
    )
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="dib-to-png",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"root_rva": root_rva, "leaf_count": leaf_count},
    )
    return AssetManifest(
        path=str(target),
        output_directory=str(out_dir),
        resource_table_present=present,
        asset_count=len(assets),
        counts=counts,
        assets=tuple(assets),
        assets_truncated=truncated,
        warnings=tuple(warnings),
        evidence=evidence,
    )



def extract_visual_assets(
    path: str | Path,
    output_directory: str | Path,
    max_assets: int = MAX_ASSETS,
) -> AssetManifest:
    """Extract a PE's real icons/bitmaps/cursors as PNG files plus a manifest.

    Walks the resource directory (reusing the pe_resources seam), decodes
    RT_GROUP_ICON/RT_GROUP_CURSOR headers to find their RT_ICON/RT_CURSOR DIB
    payloads, decodes RT_BITMAP payloads directly, and writes one PNG per
    asset into ``output_directory`` (created). Cursor hotspots come from the
    group entries. Deterministic: same input gives byte-identical PNGs and an
    identical manifest.

    Raises:
        AnalysisError: When the file is missing, unreadable, too large or not
            a PE. Malformed resource payloads only produce warnings.
    """
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(f"file too large: {size} bytes (limit {MAX_FILE_BYTES})")
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read {str(target)!r}: {exc}") from exc

    out_dir = Path(output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    image = _parse_pe_image(data)
    present = len(image.directories) > 2 and image.directories[2] != (0, 0)
    if not present:
        return _manifest(
            target, out_dir, [], warnings,
            truncated=False, present=False, root_rva=None, leaf_count=0,
        )
    root_rva = image.directories[2][0]
    root_off = _rva_to_offset(image, root_rva)
    if root_off is None:
        return _manifest(
            target, out_dir, [], warnings,
            truncated=False, present=False, root_rva=None, leaf_count=0,
        )

    collector: list[_Leaf] = []
    budget = {"dirs": MAX_DIRECTORIES}
    _walk_directory(data, root_off, root_off, budget, collector, -1, "", "", -1, 0)

    # Id -> leaf maps for the image payloads the group headers point at.
    icon_blobs: dict[int, _Leaf] = {}
    cursor_blobs: dict[int, _Leaf] = {}
    for leaf in collector:
        rid = _int_or_none(leaf.name)
        if rid is None:
            continue
        if leaf.type_id == RT_ICON:
            icon_blobs.setdefault(rid, leaf)
        elif leaf.type_id == RT_CURSOR:
            cursor_blobs.setdefault(rid, leaf)

    used_names: set[str] = set()
    assets: list[dict[str, Any]] = []
    state = {"truncated": False}



    def record(
        kind: str,
        group: str,
        rid: int,
        decoded: tuple[Any, int, int, int],
        png_bytes: bytes,
        path_png: Path,
        hotspot: dict[str, int] | None,
    ) -> None:
        _rows, width, height, bitcount = decoded
        assets.append(
            {
                "group": group,
                "kind": kind,
                "resource_id": rid,
                "width": width,
                "height": height,
                "bitcount": bitcount,
                "hotspot": hotspot,
                "path": str(path_png),
                "bytes": len(png_bytes),
                "sha256": hashlib.sha256(png_bytes).hexdigest(),
            }
        )

    def budget_left() -> bool:
        if len(assets) >= max_assets:
            state["truncated"] = True
            return False
        return True

    group_specs = [
        (leaf, "icon", icon_blobs)
        for leaf in collector
        if leaf.type_id == RT_GROUP_ICON
    ]
    group_specs += [
        (leaf, "cursor", cursor_blobs)
        for leaf in collector
        if leaf.type_id == RT_GROUP_CURSOR
    ]
    for group_leaf, kind, blob_map in group_specs:
        if not budget_left():
            warnings.append(f"asset budget {max_assets} reached; remaining groups skipped")
            break
        blob = _fetch_blob(data, image, group_leaf, warnings)
        if not blob:
            continue
        label = f"group '{group_leaf.name}'"
        entries = _parse_group_blob(blob, label, warnings)
        group_name = _sanitize_component(group_leaf.name)
        image_type = RT_ICON if kind == "icon" else RT_CURSOR
        for entry in entries:
            if not budget_left():
                warnings.append(f"asset budget {max_assets} reached; '{group_name}' truncated")
                break
            image_leaf = blob_map.get(entry.resource_id)
            if image_leaf is None:
                warnings.append(
                    f"{label}: entry references missing {image_type} resource "
                    f"id {entry.resource_id}; skipped"
                )
                continue
            dib = _fetch_blob(data, image, image_leaf, warnings)
            if not dib:
                continue
            decoded = _decode_dib(
                dib,
                double_height=True,
                label=f"{label} id {entry.resource_id}",
                warnings=warnings,
            )
            if decoded is None:
                continue
            hotspot = None
            if kind == "cursor":
                hotspot = {"x": entry.planes, "y": entry.bit_count}
            path_png = _unique_name(
                out_dir, group_name, entry.resource_id, decoded[1], decoded[2], used_names
            )
            png_bytes = encode_png(decoded[1], decoded[2], decoded[0], color_type=6)
            path_png.write_bytes(png_bytes)
            record(kind, group_name, entry.resource_id, decoded, png_bytes, path_png, hotspot)


    bitmap_leaves = [leaf for leaf in collector if leaf.type_id == RT_BITMAP]
    for position, leaf in enumerate(bitmap_leaves, start=1):
        if not budget_left():
            warnings.append(f"asset budget {max_assets} reached; remaining bitmaps skipped")
            break
        blob = _fetch_blob(data, image, leaf, warnings)
        if not blob:
            continue
        decoded = _decode_dib(
            blob, double_height=False, label=f"bitmap '{leaf.name}'", warnings=warnings
        )
        if decoded is None:
            continue
        rid = _int_or_none(leaf.name)
        if rid is None:
            rid = position
        group_name = _sanitize_component(leaf.name)
        path_png = _unique_name(out_dir, group_name, rid, decoded[1], decoded[2], used_names)
        png_bytes = encode_png(decoded[1], decoded[2], decoded[0], color_type=6)
        path_png.write_bytes(png_bytes)
        record("bitmap", group_name, rid, decoded, png_bytes, path_png, None)

    assets.sort(
        key=lambda asset: (
            _KIND_ORDER[asset["kind"]],
            asset["group"],
            asset["resource_id"],
            asset["width"],
            asset["height"],
        )
    )
    return _manifest(
        target, out_dir, assets, warnings,
        truncated=bool(state["truncated"]), present=True,
        root_rva=root_rva, leaf_count=len(collector),
    )

"""PE visual-asset extractor tests (lane-assets).

Every fixture is a hand-packed PE32+ image whose resource directory carries
hand-built ``GRPICONDIR``/``GRPICONDIRENTRY`` group headers and hand-packed
DIB payloads (BITMAPINFOHEADER + bottom-up BGRA pixel rows + 1bpp AND-mask
rows) -- struct.pack all the way down, no real binaries, no network, no
external tools. Decoded PNGs are verified by round-tripping them through
:func:`codevanta.analysis.png_diff.decode_png`.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import winres_assets
from codevanta.analysis.png_diff import decode_png
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

SECTION_VA = 0x1000
OPT_SIZE = 240  # PE32+ optional header


def _align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def make_pe(
    path: Path,
    *,
    data_dirs: dict[int, tuple[int, int]] | None = None,
    section_payload: bytes = b"",
    section_va: int = SECTION_VA,
) -> Path:
    """Build a minimal PE32+ with one ``.rsrc`` section (identity RVA map)."""
    data_dirs = data_dirs or {}
    num_sections = 1
    headers_size = _align(0x80 + 24 + OPT_SIZE + 40 * num_sections, 16)
    payload_off = headers_size
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = bytearray(24)
    coff[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", coff, 4, 0x8664, num_sections, 0, 0, 0, OPT_SIZE, 0x0022)
    opt = bytearray(OPT_SIZE)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, section_va + 0x10)
    struct.pack_into("<H", opt, 70, 0x0640)
    struct.pack_into("<I", opt, 108, 16)
    for index, (rva, size) in data_dirs.items():
        struct.pack_into("<II", opt, 112 + 8 * index, rva, size)
    section = bytearray(40)
    section[0:6] = b".rsrc\x00"
    struct.pack_into(
        "<IIII",
        section, 8,
        len(section_payload), section_va, len(section_payload), payload_off,
    )
    out = bytearray(dos) + coff + opt + section
    out += bytes(headers_size - len(out))
    out += section_payload
    path.write_bytes(bytes(out))
    return path


def build_resource_section(
    resources: dict[int, list[tuple[int | str, bytes]]],
) -> bytes:
    """Pack a 3-level resource directory (type -> name -> language) + payloads.

    ``resources`` maps a type id to its ``(name, payload)`` leaves. ``name``
    is either an integer id or a UTF-16 string name (packed as a real
    directory name blob, 0x80000000-flagged offset). All sub-directory
    offsets are relative to the root at payload offset 0; data entries point
    at ``SECTION_VA + payload offset``.
    """
    num_types = len(resources)
    cursor = 16 + 8 * num_types  # root directory
    type_dir_off: dict[int, int] = {}
    for type_id in resources:
        type_dir_off[type_id] = cursor
        cursor += 16 + 8 * len(resources[type_id])
    name_dir_off: dict[tuple[int, int], int] = {}
    for type_id, items in resources.items():
        for index in range(len(items)):
            name_dir_off[(type_id, index)] = cursor
            cursor += 24  # directory header + one entry
    data_entry_off: dict[tuple[int, int], int] = {}
    for type_id, items in resources.items():
        for index in range(len(items)):
            data_entry_off[(type_id, index)] = cursor
            cursor += 16
    name_blob_off: dict[tuple[int, int], int] = {}
    for type_id, items in resources.items():
        for index, (name, _payload) in enumerate(items):
            if isinstance(name, str):
                name_blob_off[(type_id, index)] = cursor
                cursor += 2 + 2 * len(name)
    payload_off: dict[tuple[int, int], int] = {}
    for type_id, items in resources.items():
        for index, (_name, payload) in enumerate(items):
            cursor = _align(cursor)
            payload_off[(type_id, index)] = cursor
            cursor += len(payload)

    buf = bytearray(cursor)
    struct.pack_into("<IIHHHH", buf, 0, 0, 0, 0, 0, 0, num_types)
    for pos, type_id in enumerate(resources):
        struct.pack_into(
            "<II", buf, 16 + 8 * pos, type_id, 0x80000000 | type_dir_off[type_id]
        )
    for type_id, items in resources.items():
        base = type_dir_off[type_id]
        struct.pack_into("<IIHHHH", buf, base, 0, 0, 0, 0, 0, len(items))
        for index, (name, payload) in enumerate(items):
            if isinstance(name, str):
                name_field = 0x80000000 | name_blob_off[(type_id, index)]
            else:
                name_field = name
            struct.pack_into(
                "<II",
                buf, base + 16 + 8 * index,
                name_field, 0x80000000 | name_dir_off[(type_id, index)],
            )
            name_base = name_dir_off[(type_id, index)]
            struct.pack_into("<IIHHHH", buf, name_base, 0, 0, 0, 0, 0, 1)
            struct.pack_into("<II", buf, name_base + 16, 0, data_entry_off[(type_id, index)])
            struct.pack_into(
                "<II",
                buf, data_entry_off[(type_id, index)],
                SECTION_VA + payload_off[(type_id, index)], len(payload),
            )
            if isinstance(name, str):
                raw = name.encode("utf-16-le")
                off = name_blob_off[(type_id, index)]
                struct.pack_into("<H", buf, off, len(name))
                buf[off + 2 : off + 2 + len(raw)] = raw
            off = payload_off[(type_id, index)]
            buf[off : off + len(payload)] = payload
    return bytes(buf)



# ---- hand-packed DIB + group builders ---------------------------------------------


def bmi_header(width: int, height: int, bitcount: int) -> bytes:
    """40-byte BITMAPINFOHEADER (BI_RGB, biSizeImage 0 -- optional for BI_RGB)."""
    return struct.pack(
        "<IiiHHIIiiII", 40, width, height, 1, bitcount, 0, 0, 0, 0, 0, 0
    )


def dib_icon_32bpp(
    width: int,
    height: int,
    pixels_bottomup: list[list[tuple[int, int, int, int]]],
    mask_bits_bottomup: list[list[bool]],
) -> bytes:
    """Pack an icon/cursor DIB: header + bottom-up BGRA rows + 1bpp AND mask.

    ``pixels_bottomup`` holds ``height`` rows of ``(b, g, r, a)`` tuples in
    bottom-up DIB order; ``mask_bits_bottomup`` holds ``height`` mask rows of
    per-pixel booleans (True = transparent) in bottom-up order. biHeight is
    doubled (pixel rows + mask rows), rows are 4-byte aligned.
    """
    header = bmi_header(width, height * 2, 32)
    stride = ((width * 32 + 31) // 32) * 4
    pixels = bytearray()
    for row in pixels_bottomup:
        rowbytes = bytearray()
        for b, g, r, a in row:
            rowbytes += bytes((b, g, r, a))
        rowbytes += bytes(stride - len(rowbytes))
        pixels += rowbytes
    mask_stride = ((width + 31) // 32) * 4
    masks = bytearray()
    for row in mask_bits_bottomup:
        rowbytes = bytearray(mask_stride)
        for x, transparent in enumerate(row):
            if transparent:
                rowbytes[x >> 3] |= 0x80 >> (x & 7)
        masks += rowbytes
    return header + bytes(pixels) + bytes(masks)


def dib_bitmap_24bpp(width: int, height: int, pixels_bottomup: list[list[tuple[int, int, int]]]) -> bytes:
    """Pack an RT_BITMAP DIB: header + bottom-up BGR rows (no AND mask)."""
    header = bmi_header(width, height, 24)
    stride = ((width * 24 + 31) // 32) * 4
    pixels = bytearray()
    for row in pixels_bottomup:
        rowbytes = bytearray()
        for b, g, r in row:
            rowbytes += bytes((b, g, r))
        rowbytes += bytes(stride - len(rowbytes))
        pixels += rowbytes
    return header + bytes(pixels)


def group_blob(kind: int, entries: list[tuple[int, int, int, int, int, int, int, int]]) -> bytes:
    """GRPICONDIR (reserved 0, type, count) + GRPICONDIRENTRY records."""
    out = struct.pack("<HHH", 0, kind, len(entries))
    for entry in entries:
        out += struct.pack("<BBBBHHIH", *entry)
    return out


RGBA_ICON_1_TOP = [(0x10, 0x20, 0x30, 0xFF), (0x40, 0x50, 0x60, 0x80)]
RGBA_ICON_1_BOTTOM = [(0x11, 0x22, 0x33, 0xFF), (0x44, 0x55, 0x66, 0xFF)]


def icon1_dib() -> bytes:
    """2x2 32bpp icon with real alpha: bottom-up rows, all-zero AND mask."""
    bgra_top = [(p[2], p[1], p[0], p[3]) for p in RGBA_ICON_1_TOP]
    bgra_bottom = [(p[2], p[1], p[0], p[3]) for p in RGBA_ICON_1_BOTTOM]
    return dib_icon_32bpp(
        2, 2,
        [bgra_bottom, bgra_top],  # DIB row 0 is the output bottom row
        [[False, False], [False, False]],
    )


RGBA_ICON_2 = [(0xA0, 0xB0, 0xC0), (0xD0, 0xE0, 0xF0)]


def icon2_dib() -> bytes:
    """2x2 32bpp icon with all alpha bytes zero: the AND mask decides."""
    bgra = [(p[2], p[1], p[0], 0) for p in RGBA_ICON_2]
    return dib_icon_32bpp(
        2, 2,
        [bgra, bgra],
        [[False, False], [True, False]],  # top row pixel 0 transparent
    )


RGBA_BMP_TOP = [(0x10, 0x20, 0x30), (0x40, 0x50, 0x60)]


def bmp_dib() -> bytes:
    """2x1 24bpp RT_BITMAP: one real-height row, BGR, 4-byte aligned."""
    bgr = [(p[2], p[1], p[0]) for p in RGBA_BMP_TOP]
    return dib_bitmap_24bpp(2, 1, [bgr])


RGBA_CURSOR_TOP = [(0x77, 0x88, 0x99, 0xFF), (0xAA, 0xBB, 0xCC, 0xFF)]
RGBA_CURSOR_BOTTOM = [(0x01, 0x02, 0x03, 0xFF), (0x04, 0x05, 0x06, 0xFF)]


def cursor_dib() -> bytes:
    """2x2 32bpp cursor image with real alpha (hotspot lives in the group)."""
    bgra_top = [(p[2], p[1], p[0], p[3]) for p in RGBA_CURSOR_TOP]
    bgra_bottom = [(p[2], p[1], p[0], p[3]) for p in RGBA_CURSOR_BOTTOM]
    return dib_icon_32bpp(
        2, 2,
        [bgra_bottom, bgra_top],
        [[False, False], [False, False]],
    )


def assets_pe(path: Path) -> Path:
    """One PE carrying an icon group (2 entries), a cursor group and a bitmap."""
    payload = build_resource_section(
        {
            14: [("APPICON", group_blob(1, [
                (2, 2, 0, 0, 1, 32, len(icon1_dib()), 1),
                (2, 2, 0, 0, 1, 32, len(icon2_dib()), 2),
            ])), ("BADICON", group_blob(1, [
                (2, 2, 0, 0, 1, 32, 40, 3),
            ]))],  # RT_GROUP_ICON (BADICON references the malformed id 3)
            12: [("CURSOR", group_blob(2, [
                (2, 2, 0, 0, 3, 7, len(cursor_dib()), 1),
            ]))],  # RT_GROUP_CURSOR: planes/bitCount carry hotspot (3, 7)
            3: [  # RT_ICON image payloads (referenced by id)
                (1, icon1_dib()),
                (2, icon2_dib()),
                (3, b"\xef\xbe\xad\xde" + b"\x00" * 36),  # malformed biSize
            ],
            1: [(1, cursor_dib())],  # RT_CURSOR image payload
            2: [("BMP", bmp_dib())],  # RT_BITMAP
        }
    )
    return make_pe(path, data_dirs={2: (SECTION_VA, len(payload))}, section_payload=payload)



# ---- decode assertions ------------------------------------------------------------


def test_icon_group_decode_writes_matching_pngs(tmp_path: Path) -> None:
    out = tmp_path / "png"
    manifest = winres_assets.extract_visual_assets(assets_pe(tmp_path / "app.exe"), out)
    assert manifest.resource_table_present is True
    assert manifest.asset_count == 4  # 2 icons + 1 cursor + 1 bitmap
    assert manifest.counts == {"icon": 2, "cursor": 1, "bitmap": 1}
    icon = next(a for a in manifest.assets if a["group"] == "APPICON" and a["resource_id"] == 1)
    assert icon["kind"] == "icon"
    assert (icon["width"], icon["height"], icon["bitcount"]) == (2, 2, 32)
    assert Path(icon["path"]).name == "APPICON_1_2x2.png"
    png_bytes = Path(icon["path"]).read_bytes()
    assert icon["bytes"] == len(png_bytes)
    assert icon["sha256"] == hashlib.sha256(png_bytes).hexdigest()
    image = decode_png(png_bytes)
    assert (image.width, image.height) == (2, 2)
    assert image.pixels[0] == tuple(tuple(p) for p in RGBA_ICON_1_TOP)
    assert image.pixels[1] == tuple(tuple(p) for p in RGBA_ICON_1_BOTTOM)


def test_zero_alpha_icon_falls_back_to_and_mask(tmp_path: Path) -> None:
    out = tmp_path / "png"
    manifest = winres_assets.extract_visual_assets(assets_pe(tmp_path / "app.exe"), out)
    icon2 = next(a for a in manifest.assets if a["resource_id"] == 2 and a["kind"] == "icon")
    image = decode_png(Path(icon2["path"]).read_bytes())
    # AND-mask pixel (top row, x=0) is transparent; every other pixel is opaque.
    assert image.pixels[0][0] == (0xA0, 0xB0, 0xC0, 0)
    assert image.pixels[0][1] == (0xD0, 0xE0, 0xF0, 255)
    assert image.pixels[1][0] == (0xA0, 0xB0, 0xC0, 255)
    assert image.pixels[1][1] == (0xD0, 0xE0, 0xF0, 255)



def test_rt_bitmap_decodes_at_real_height_without_mask(tmp_path: Path) -> None:
    out = tmp_path / "png"
    manifest = winres_assets.extract_visual_assets(assets_pe(tmp_path / "app.exe"), out)
    bitmap = next(a for a in manifest.assets if a["kind"] == "bitmap")
    assert bitmap["group"] == "BMP"
    assert (bitmap["width"], bitmap["height"], bitmap["bitcount"]) == (2, 1, 24)
    assert Path(bitmap["path"]).name == "BMP_1_2x1.png"
    image = decode_png(Path(bitmap["path"]).read_bytes())
    assert (image.width, image.height) == (2, 1)
    assert image.pixels[0][0] == (0x10, 0x20, 0x30, 255)
    assert image.pixels[0][1] == (0x40, 0x50, 0x60, 255)
    assert bitmap["hotspot"] is None


def test_cursor_group_records_hotspot(tmp_path: Path) -> None:
    out = tmp_path / "png"
    manifest = winres_assets.extract_visual_assets(assets_pe(tmp_path / "app.exe"), out)
    cursor = next(a for a in manifest.assets if a["kind"] == "cursor")
    assert cursor["group"] == "CURSOR"
    assert cursor["resource_id"] == 1
    assert cursor["hotspot"] == {"x": 3, "y": 7}
    image = decode_png(Path(cursor["path"]).read_bytes())
    assert image.pixels[0][0] == (0x77, 0x88, 0x99, 255)
    assert image.pixels[1][1] == (0x04, 0x05, 0x06, 255)


def test_malformed_dib_is_warned_and_skipped(tmp_path: Path) -> None:
    out = tmp_path / "png"
    manifest = winres_assets.extract_visual_assets(assets_pe(tmp_path / "bad.exe"), out)
    assert manifest.asset_count == 4  # the malformed icon is skipped, others survive
    assert not any(a["group"] == "BADICON" for a in manifest.assets)
    assert any("malformed DIB" in warning for warning in manifest.warnings)


def test_pe_without_image_resources_is_valid_empty(tmp_path: Path) -> None:
    payload = build_resource_section({6: [(1, struct.pack("<H", 0))]})
    target = make_pe(
        tmp_path / "strings.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    manifest = winres_assets.extract_visual_assets(target, tmp_path / "out")
    assert manifest.asset_count == 0
    assert manifest.counts == {"icon": 0, "cursor": 0, "bitmap": 0}
    assert manifest.assets == ()
    assert manifest.assets_truncated is False
    assert manifest.resource_table_present is True


def test_pe_without_resource_table_is_valid_empty(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "bare.exe")
    manifest = winres_assets.extract_visual_assets(target, tmp_path / "out")
    assert manifest.asset_count == 0
    assert manifest.resource_table_present is False


def test_missing_file_is_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        winres_assets.extract_visual_assets(tmp_path / "ghost.exe", tmp_path / "out")



def test_extraction_is_deterministic(tmp_path: Path) -> None:
    target = assets_pe(tmp_path / "same.exe")
    manifest_a = winres_assets.extract_visual_assets(target, tmp_path / "a")
    manifest_b = winres_assets.extract_visual_assets(target, tmp_path / "b")
    # Same input -> same asset records (modulo output paths) and identical
    # PNG bytes, proven by the sha256 sequence.
    stripped = lambda manifest: [  # noqa: E731
        {key: value for key, value in asset.items() if key != "path"}
        for asset in manifest.assets
    ]
    assert stripped(manifest_a) == stripped(manifest_b)
    assert manifest_a.counts == manifest_b.counts
    assert manifest_a.warnings == manifest_b.warnings
    for asset in manifest_a.assets:
        assert asset["sha256"] == hashlib.sha256(
            Path(asset["path"]).read_bytes()
        ).hexdigest()


def test_manifest_is_json_safe(tmp_path: Path) -> None:
    manifest = winres_assets.extract_visual_assets(
        assets_pe(tmp_path / "j.exe"), tmp_path / "out"
    )
    payload = manifest.to_dict()
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert manifest.evidence.source == "pe.assets"
    assert manifest.evidence.method == "dib-to-png"


def test_group_names_cannot_traverse(tmp_path: Path) -> None:
    safe = winres_assets._sanitize_component("../../evil")
    assert "/" not in safe and "\\" not in safe
    assert Path(safe).name == safe
    assert ".." not in Path(safe).parts


# ---- MCP tool surface -------------------------------------------------------------


def test_mcp_pe_assets_tool(tmp_path: Path) -> None:
    target = assets_pe(tmp_path / "mcp.exe")
    out = tmp_path / "png"
    payload = tools.codevanta_pe_assets(str(target), str(out))
    assert payload["asset_count"] == 4
    assert payload["counts"] == {"icon": 2, "cursor": 1, "bitmap": 1}
    names = {Path(asset["path"]).name for asset in payload["assets"]}
    assert names == {
        "APPICON_1_2x2.png",
        "APPICON_2_2x2.png",
        "CURSOR_1_2x2.png",
        "BMP_1_2x1.png",
    }
    assert all((out / name).is_file() for name in names)
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_pe_assets(str(tmp_path / "ghost.exe"), str(tmp_path / "elsewhere"))

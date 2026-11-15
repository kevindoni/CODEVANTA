"""Win32 UI-resource decoder tests (lane-uistatic).

Every fixture is a hand-packed PE32+ image whose resource directory carries
hand-built ``DLGTEMPLATEEX``/``DLGTEMPLATE``/``MENUTEMPLATE``/``MENUEX``/
``RT_STRING`` blobs -- struct.pack all the way down, no real binaries, no
network, no external tools. Malformed cases prove the typed
:class:`~codevanta.core.report.AnalysisError`.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import winres_ui
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

SECTION_VA = 0x1000
OPT_SIZE = {0x20B: 240, 0x10B: 224}

DS_SETFONT = 0x40
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_POPUP = 0x80000000
WS_TABSTOP = 0x00010000
ES_AUTOHSCROLL = 0x80

MF_POPUP = 0x10
MF_END = 0x80
MENUEX_POPUP = 0x01
MENUEX_END = 0x80


def _align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _u16(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def make_pe(
    path: Path,
    *,
    data_dirs: dict[int, tuple[int, int]] | None = None,
    section_payload: bytes = b"",
    section_va: int = SECTION_VA,
    num_dirs: int = 16,
) -> Path:
    """Build a minimal PE32+ with one ``.rsrc`` section (identity RVA map)."""
    data_dirs = data_dirs or {}
    opt_size = OPT_SIZE[0x20B]
    num_sections = 1
    headers_size = _align(0x80 + 24 + opt_size + 40 * num_sections, 16)
    payload_off = headers_size
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = bytearray(24)
    coff[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", coff, 4, 0x8664, num_sections, 0, 0, 0, opt_size, 0x0022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, section_va + 0x10)
    struct.pack_into("<H", opt, 70, 0x0640)
    struct.pack_into("<I", opt, 108, num_dirs)
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
    resources: dict[int, list[tuple[int, bytes]]],
) -> bytes:
    """Pack a 3-level resource directory (type -> name -> language) + payloads.

    ``resources`` maps a type id to its ``(name id, payload)`` leaves. All
    sub-directory offsets are relative to the root, which sits at payload
    offset 0, so data entries point at ``SECTION_VA + payload offset``.
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
            struct.pack_into(
                "<II",
                buf, base + 16 + 8 * index,
                name, 0x80000000 | name_dir_off[(type_id, index)],
            )
            name_base = name_dir_off[(type_id, index)]
            struct.pack_into("<IIHHHH", buf, name_base, 0, 0, 0, 0, 0, 1)
            struct.pack_into("<II", buf, name_base + 16, 0, data_entry_off[(type_id, index)])
            struct.pack_into(
                "<II",
                buf, data_entry_off[(type_id, index)],
                SECTION_VA + payload_off[(type_id, index)], len(payload),
            )
            off = payload_off[(type_id, index)]
            buf[off : off + len(payload)] = payload
    return bytes(buf)


def _align_blob(blob: bytearray) -> bytearray:
    while len(blob) % 4:
        blob += b"\x00"
    return blob


def build_dialog_ex() -> bytes:
    """DLGTEMPLATEEX: title 'Main', font block, BUTTON id=1 'OK', EDIT id=2."""
    blob = bytearray()
    blob += struct.pack("<HH", 1, 0xFFFF)  # dlgVer, signature
    blob += struct.pack("<III", 42, 0, WS_POPUP | WS_VISIBLE | DS_SETFONT)
    blob += struct.pack("<H", 2)  # cDlgItems
    blob += struct.pack("<hhhh", 10, 20, 300, 140)
    blob += struct.pack("<H", 0x0000)  # menu: none
    blob += struct.pack("<H", 0x0000)  # class: none
    blob += _u16("Main")  # title
    blob += struct.pack("<HHBB", 8, 400, 0, 0)  # EX font: pt, weight, italic, charset
    blob += _u16("Segoe UI")  # typeface
    _align_blob(blob)
    # item 1: BUTTON, id 1, 'OK'
    blob += struct.pack("<IIIhhhhI", 0, 0, WS_CHILD | WS_VISIBLE, 100, 100, 50, 14, 1)
    blob += struct.pack("<HH", 0xFFFF, 0x80)  # class ordinal BUTTON
    blob += _u16("OK")
    blob += struct.pack("<H", 0)  # extraCount
    _align_blob(blob)
    # item 2: EDIT, id 2, no title
    blob += struct.pack(
        "<IIIhhhhI",
        0, 0x00000200, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        10, 10, 200, 12, 2,
    )
    blob += struct.pack("<HH", 0xFFFF, 0x81)  # class ordinal EDIT
    blob += struct.pack("<H", 0x0000)  # empty title
    blob += struct.pack("<H", 0)  # extraCount
    blob += struct.pack("<H", 0)  # template terminator
    return bytes(blob)


def build_dialog_classic() -> bytes:
    """DLGTEMPLATE (classic): WORD ids, ordinal menu reference, classic font."""
    blob = bytearray()
    blob += struct.pack("<II", WS_POPUP | WS_VISIBLE | DS_SETFONT, 0)  # style, exStyle
    blob += struct.pack("<H", 1)  # cdit
    blob += struct.pack("<hhhh", 0, 0, 200, 100)
    blob += struct.pack("<HH", 0xFFFF, 5)  # menu: ordinal 5
    blob += struct.pack("<H", 0x0000)  # class: none
    blob += _u16("Cfg")
    blob += struct.pack("<H", 8)  # classic font: pointsize
    blob += _u16("Arial")
    _align_blob(blob)
    blob += struct.pack("<IIhhhhH", WS_CHILD | WS_VISIBLE | 0x1, 0, 50, 70, 50, 14, 9)
    blob += struct.pack("<HH", 0xFFFF, 0x80)  # BUTTON
    blob += _u16("Go")
    blob += struct.pack("<H", 0)
    blob += struct.pack("<H", 0)
    return bytes(blob)


def build_menu_classic() -> bytes:
    """Classic MENUTEMPLATE: popup File with New (101) and Exit (102)."""
    blob = bytearray()
    blob += struct.pack("<HH", 0, 4)  # version 0, items start at 4
    blob += struct.pack("<H", MF_POPUP) + _u16("File")
    blob += struct.pack("<HH", 0, 101) + _u16("New")
    blob += struct.pack("<HH", MF_END, 102) + _u16("Exit")
    return bytes(blob)


def build_menu_ex() -> bytes:
    """MENUEX template: popup File (last) with New 101 and Exit 102."""
    blob = bytearray()
    blob += struct.pack("<HHI", 1, 4, 7)  # version, offset, helpId
    blob += struct.pack("<IIIH", 0, 0, 0, MENUEX_POPUP | MENUEX_END)  # File popup
    blob += _u16("File")
    while len(blob) % 4:
        blob += b"\x00"
    blob += struct.pack("<I", 0)  # popup dwHelpId
    blob += struct.pack("<IIIH", 0, 0, 101, 0) + _u16("New")
    while len(blob) % 4:
        blob += b"\x00"
    blob += struct.pack("<IIIH", 0, 0, 102, MENUEX_END) + _u16("Exit")
    while len(blob) % 4:
        blob += b"\x00"
    return bytes(blob)


def build_string_block() -> bytes:
    """RT_STRING block 1: slots Alpha/Beta/Gamma plus one empty slot."""
    blob = bytearray()
    for text in ("Alpha", "Beta", "Gamma"):
        blob += struct.pack("<H", len(text)) + text.encode("utf-16-le")
    blob += struct.pack("<H", 0)  # empty slot 4; slots 5..16 omitted
    return bytes(blob)


def ui_pe(path: Path) -> Path:
    """One PE carrying one dialog (EX), one classic menu, one string block."""
    payload = build_resource_section(
        {
            5: [(1, build_dialog_ex())],  # RT_DIALOG
            4: [(1, build_menu_classic())],  # RT_MENU
            6: [(1, build_string_block())],  # RT_STRING
        }
    )
    return make_pe(path, data_dirs={2: (SECTION_VA, len(payload))}, section_payload=payload)


# ---- decode assertions ---------------------------------------------------------


def test_dialog_ex_decode(tmp_path: Path) -> None:
    summary = winres_ui.decode_ui_resources(ui_pe(tmp_path / "ui.exe"))
    assert summary.resource_table_present is True
    assert summary.dialog_count == 1
    assert summary.dialog_item_count == 2
    assert summary.warnings == ()
    dialog = summary.dialogs[0]
    assert dialog["form"] == "ex"
    assert dialog["title"] == "Main"
    assert dialog["help_id"] == 42
    assert dialog["font"] == {
        "point_size": 8,
        "weight": 400,
        "italic": 0,
        "charset": 0,
        "typeface": "Segoe UI",
    }
    # DLU -> px approximation: 4 px per x-DLU, 8 px per y-DLU.
    assert dialog["rect_dlu"] == [10, 20, 300, 140]
    assert dialog["rect_px"] == [40, 160, 1200, 1120]
    button, edit = dialog["items"]
    assert button["class"] == "BUTTON"
    assert button["title"] == "OK"
    assert button["id"] == 1
    assert button["rect_dlu"] == [100, 100, 50, 14]
    assert button["rect_px"] == [400, 800, 200, 112]
    assert edit["class"] == "EDIT"
    assert edit["title"] == ""
    assert edit["id"] == 2
    assert edit["rect_px"] == [40, 80, 800, 96]


def test_string_table_block_ids(tmp_path: Path) -> None:
    summary = winres_ui.decode_ui_resources(ui_pe(tmp_path / "strings.exe"))
    assert summary.stringtable_block_count == 1
    assert summary.stringtable_entry_count == 3
    assert [
        (entry["id"], entry["text"]) for entry in summary.stringtable_entries
    ] == [(1, "Alpha"), (2, "Beta"), (3, "Gamma")]


def test_menu_tree_classic(tmp_path: Path) -> None:
    summary = winres_ui.decode_ui_resources(ui_pe(tmp_path / "menu.exe"))
    assert summary.menu_count == 1
    menu = summary.menus[0]
    assert menu["kind"] == "classic"
    assert menu["item_count"] == 3
    popup = menu["items"][0]
    assert popup["text"] == "File"
    assert popup["popup"] is True
    assert [child["id"] for child in popup["children"]] == [101, 102]
    assert [child["text"] for child in popup["children"]] == ["New", "Exit"]


def test_menu_ex_tree(tmp_path: Path) -> None:
    payload = build_resource_section({4: [(1, build_menu_ex())]})
    target = make_pe(
        tmp_path / "menuex.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    summary = winres_ui.decode_ui_resources(target)
    menu = summary.menus[0]
    assert menu["kind"] == "menuex"
    popup = menu["items"][0]
    assert popup["text"] == "File"
    assert popup["popup"] is True
    assert [child["id"] for child in popup["children"]] == [101, 102]


def test_dialog_classic_decode(tmp_path: Path) -> None:
    payload = build_resource_section({5: [(1, build_dialog_classic())]})
    target = make_pe(
        tmp_path / "classic.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    summary = winres_ui.decode_ui_resources(target)
    dialog = summary.dialogs[0]
    assert dialog["form"] == "classic"
    assert dialog["title"] == "Cfg"
    assert dialog["font"] == {"point_size": 8, "typeface": "Arial"}
    assert dialog["menu"] == 5  # menu referenced by ordinal
    item = dialog["items"][0]
    assert (item["id"], item["class"], item["title"]) == (9, "BUTTON", "Go")
    assert item["rect_px"] == [200, 560, 200, 112]


# ---- empty-but-valid, determinism, JSON safety ----------------------------------


def test_pe_without_ui_resources_is_valid(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "bare.exe")  # no resource directory at all
    summary = winres_ui.decode_ui_resources(target)
    assert summary.resource_table_present is False
    assert summary.dialog_count == 0
    assert summary.dialogs == ()
    assert summary.menus == ()
    assert summary.stringtable_entry_count == 0
    assert summary.evidence.to_dict()["method"] == "data-directory-2-empty"


def test_preview_html_deterministic(tmp_path: Path) -> None:
    summary = winres_ui.decode_ui_resources(ui_pe(tmp_path / "ui.exe"))
    first = winres_ui.render_preview_html(summary, title="Fixture UI")
    second = winres_ui.render_preview_html(summary, title="Fixture UI")
    assert first == second
    assert "<!DOCTYPE html>" in first
    assert "BUTTON" in first  # class name in the data-class attribute
    assert ">EDIT</div>" in first  # untitled item falls back to its class name
    assert ">OK</div>" in first
    assert 'data-id="1"' in first
    assert 'data-id="2"' in first
    assert "New" in first and "Exit" in first
    assert "Alpha" in first
    assert "DLUs" in first  # honest approximation note


def test_summary_to_dict_is_json_safe(tmp_path: Path) -> None:
    summary = winres_ui.decode_ui_resources(ui_pe(tmp_path / "ui.exe"))
    payload = summary.to_dict()
    assert json.loads(json.dumps(payload)) == payload


# ---- typed errors ---------------------------------------------------------------


def test_missing_file_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        winres_ui.decode_ui_resources(tmp_path / "ghost.exe")


def test_truncated_dialog_mid_item_typed_error(tmp_path: Path) -> None:
    blob = build_dialog_ex()
    truncated = blob[:-20]  # cut into item 2's fixed header
    payload = build_resource_section({5: [(1, truncated)]})
    target = make_pe(
        tmp_path / "cut.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    with pytest.raises(AnalysisError, match="truncated dialog template at offset"):
        winres_ui.decode_ui_resources(target)


def test_unknown_ex_signature_typed_error(tmp_path: Path) -> None:
    blob = struct.pack("<HH", 0xFFFF, 0xBEEF) + b"\x00" * 8
    payload = build_resource_section({5: [(1, blob)]})
    target = make_pe(
        tmp_path / "badsig.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    with pytest.raises(AnalysisError, match="unknown dialog template signature"):
        winres_ui.decode_ui_resources(target)


def test_item_count_mismatch_typed_error(tmp_path: Path) -> None:
    blob = build_dialog_ex()
    patched = bytearray(blob)
    struct.pack_into("<H", patched, 16, 9)  # declare 9 items, payload holds 2
    payload = build_resource_section({5: [(1, bytes(patched))]})
    target = make_pe(
        tmp_path / "mismatch.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    with pytest.raises(AnalysisError, match="declared 9 items"):
        winres_ui.decode_ui_resources(target)


def test_malformed_string_table_typed_error(tmp_path: Path) -> None:
    blob = struct.pack("<H", 500) + b"A" * 8  # claims 500 chars, holds 4
    payload = build_resource_section({6: [(1, blob)]})
    target = make_pe(
        tmp_path / "badstrings.exe",
        data_dirs={2: (SECTION_VA, len(payload))},
        section_payload=payload,
    )
    with pytest.raises(AnalysisError, match="malformed string table"):
        winres_ui.decode_ui_resources(target)


# ---- MCP tool surface -----------------------------------------------------------


def test_mcp_dialog_decode_tool(tmp_path: Path) -> None:
    target = ui_pe(tmp_path / "mcp.exe")
    payload = tools.codevanta_dialog_decode(str(target))
    assert payload["dialog_count"] == 1
    assert payload["dialog_item_count"] == 2
    assert payload["dialogs"][0]["items"][0]["class"] == "BUTTON"
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_dialog_decode(str(tmp_path / "ghost.exe"))


def test_mcp_ui_preview_tool(tmp_path: Path) -> None:
    target = ui_pe(tmp_path / "preview.exe")
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    manifest = tools.codevanta_ui_preview(str(target), str(out_a))
    tools.codevanta_ui_preview(str(target), str(out_b))
    assert (out_a / "ui_preview.html").is_file()
    assert (out_a / "ui_layout.json").is_file()
    assert manifest["dialog_count"] == 1
    assert manifest["dialog_item_count"] == 2
    assert manifest["menu_count"] == 1
    assert manifest["stringtable_entry_count"] == 3
    assert {Path(item["path"]).name for item in manifest["files"]} == {
        "ui_preview.html",
        "ui_layout.json",
    }
    html_a = (out_a / "ui_preview.html").read_text(encoding="utf-8")
    html_b = (out_b / "ui_preview.html").read_text(encoding="utf-8")
    assert html_a == html_b  # deterministic across calls
    assert ">OK</div>" in html_a
    layout = json.loads((out_a / "ui_layout.json").read_text(encoding="utf-8"))
    assert layout["dialogs"][0]["title"] == "Main"
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_ui_preview(str(tmp_path / "ghost.exe"), str(tmp_path / "c"))

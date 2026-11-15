"""Win32 UI-resource decoder (lane-uistatic): dialogs, menus, string tables.

Reconstructs what a binary would *look* like without running it: the
``RT_DIALOG`` ``DLGTEMPLATE``/``DLGTEMPLATEEX`` blobs in the PE resource
directory are decoded into a bounded widget tree (class, title, id, DLU rect
and an honest DLU->pixel approximation), ``RT_MENU`` templates into an item
tree and ``RT_STRING`` blocks into their effective string ids
(``(block - 1) * 16 + index``). :func:`render_preview_html` turns one summary
into a deterministic, byte-identical HTML preview (no timestamps, no
nondeterministic ordering).

The resource-directory walk itself is reused from
:mod:`codevanta.analysis.pe_resources` (its header parser, section mapping and
bounded directory walker); this module only fetches the leaf payloads and
decodes the Win32 structures inside them. Everything is pure ``struct`` +
``bytes`` -- nothing is executed. Bounds (64 dialogs, 256 items per dialog,
256 menu items, 512 string entries) are reported through ``*_truncated`` flags
and warnings instead of unbounded work. Malformed templates raise the typed
:class:`~codevanta.core.report.AnalysisError`; a PE without UI resources is a
valid, empty result -- never an error.
"""

from __future__ import annotations

import html
import json
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
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_DIALOGS",
    "MAX_ITEMS_PER_DIALOG",
    "MAX_MENU_ITEMS",
    "MAX_STRING_CHARS",
    "MAX_STRINGTABLE_ENTRIES",
    "WinResUiSummary",
    "decode_ui_resources",
    "layout_json_bytes",
    "render_preview_html",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "ui.winres"

#: Dialog / menu resources decoded per summary (bounded work).
MAX_DIALOGS = 64

#: Items decoded inside one dialog template (bounded work).
MAX_ITEMS_PER_DIALOG = 256

#: Menu items walked across one menu template (bounded work).
MAX_MENU_ITEMS = 256

#: String-table entries kept per summary (bounded work).
MAX_STRINGTABLE_ENTRIES = 512

#: Characters kept per string-table entry (bounded output).
MAX_STRING_CHARS = 256

#: ``DS_SETFONT``: the template carries a font block after the title.
DS_SETFONT = 0x40

#: ``MF_POPUP`` in classic ``MENUITEMTEMPLATE`` option words.
MF_POPUP = 0x10

#: ``MF_END`` in classic ``MENUITEMTEMPLATE`` option words.
MF_END = 0x80

#: ``bResInfo`` bit: the MENUEX item opens a submenu.
MENUEX_POPUP = 0x01

#: ``bResInfo`` bit: the MENUEX item is the last of its level.
MENUEX_END = 0x80

#: Well-known window-class ordinals used inside dialog templates (winuser.h).
WINDOW_CLASS_ORDINALS: dict[int, str] = {
    0x80: "BUTTON",
    0x81: "EDIT",
    0x82: "STATIC",
    0x83: "LISTBOX",
    0x84: "SCROLLBAR",
    0x85: "COMBOBOX",
}

#: Fixed CSS of the HTML preview (constant: same evidence, byte-identical HTML).
_PREVIEW_CSS = (
    "<style>\n"
    "body{font-family:sans-serif;margin:1em;background:#f4f4f4}\n"
    ".dialog{position:relative;background:#fff;border:1px solid #888;"
    "margin:1em 0;box-shadow:2px 2px 4px #ccc}\n"
    ".dialog-title{display:block;padding:2px 4px;border-bottom:1px solid #ddd;"
    "font-weight:bold;color:#555}\n"
    ".item{position:absolute;border:1px solid #999;background:#eee;"
    "font-size:11px;overflow:hidden;white-space:nowrap;padding:1px 2px}\n"
    ".item.button{background:#dcdcdc;border-radius:2px;text-align:center}\n"
    ".item.edit{background:#fff}\n"
    ".item.static{border:none;background:transparent}\n"
    "details{margin:0.5em 0}\n"
    "table{border-collapse:collapse}\n"
    "td,th{border:1px solid #999;padding:1px 6px;font-size:12px}\n"
    "</style>\n"
)


# ---- low-level reads ---------------------------------------------------------


def _word(blob: bytes, pos: int) -> int:
    """Read one WORD at ``pos`` (bounds-checked, names the offset on error)."""
    if pos < 0 or pos + 2 > len(blob):
        raise AnalysisError(f"truncated resource template at offset 0x{pos:x}")
    return struct.unpack_from("<H", blob, pos)[0]


def _dword(blob: bytes, pos: int) -> int:
    """Read one DWORD at ``pos`` (bounds-checked, names the offset on error)."""
    if pos < 0 or pos + 4 > len(blob):
        raise AnalysisError(f"truncated resource template at offset 0x{pos:x}")
    return struct.unpack_from("<I", blob, pos)[0]


def _short(blob: bytes, pos: int) -> int:
    """Read one signed short (DLU coordinate) at ``pos``."""
    if pos < 0 or pos + 2 > len(blob):
        raise AnalysisError(f"truncated resource template at offset 0x{pos:x}")
    return struct.unpack_from("<h", blob, pos)[0]


def _align4(pos: int) -> int:
    return (pos + 3) & ~3


def _read_utf16_z(blob: bytes, pos: int, what: str) -> tuple[str, int]:
    """Read one NUL-terminated UTF-16LE string inline at ``pos``.

    Win32 resource strings are *not* length-prefixed here: the text runs until
    the NUL code unit, which is consumed. A run-away string (no NUL before the
    end of the blob) is a typed error naming the offset.
    """
    chars: list[str] = []
    cursor = pos
    while cursor + 2 <= len(blob):
        code = struct.unpack_from("<H", blob, cursor)[0]
        cursor += 2
        if code == 0:
            return "".join(chars), cursor
        chars.append(chr(code))
        if len(chars) > 4096:
            break
    raise AnalysisError(
        f"truncated resource template at offset 0x{pos:x}: unterminated {what} string"
    )


def _read_sz_or_ord(blob: bytes, pos: int, what: str) -> tuple[int | str | None, int]:
    """Read one ``sz_Or_Ord`` field: 0x0000 none / 0xFFFF+WORD ordinal / string."""
    first = _word(blob, pos)
    if first == 0x0000:
        return None, pos + 2
    if first == 0xFFFF:
        return _word(blob, pos + 2), pos + 4
    return _read_utf16_z(blob, pos, what)


def _class_label(value: int | str | None) -> str | None:
    """Render a class ``sz_Or_Ord`` value; ordinal 0x80..0x85 map to names."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return WINDOW_CLASS_ORDINALS.get(value, f"CLASS_{value}")


def _dlu_to_px(rect: list[int]) -> list[int]:
    """Approximate dialog units as pixels: 4 px per x-DLU, 8 px per y-DLU.

    Honest approximation: the true conversion depends on the dialog font's
    average character width/height, which is unknowable offline; these
    constants are the classic system-font averages and are documented as such
    in every output.
    """
    return [rect[0] * 4, rect[1] * 8, rect[2] * 4, rect[3] * 8]


# ---- dialog templates --------------------------------------------------------


def _decode_dialog(blob: bytes, name: str, warnings: list[str]) -> dict[str, Any]:
    """Decode one ``DLGTEMPLATE``/``DLGTEMPLATEEX`` blob into a widget dict."""
    w0 = _word(blob, 0)
    w1 = _word(blob, 2)
    if w0 == 0xFFFF and w1 == 1:
        ex_form, pos = True, 4  # lane ordering: signature word first
    elif w0 == 1 and w1 == 0xFFFF:
        ex_form, pos = True, 4  # canonical winnt.h ordering: dlgVer then 0xFFFF
    elif w0 == 0xFFFF:
        raise AnalysisError(
            f"unknown dialog template signature in '{name}': first word 0xFFFF, "
            f"second word 0x{w1:04x} (expected dlgVer 1 + signature 0xFFFF)"
        )
    else:
        ex_form, pos = False, 0

    if ex_form:
        help_id: int | None = _dword(blob, pos)
        ex_style = _dword(blob, pos + 4)
        style = _dword(blob, pos + 8)
        item_count = _word(blob, pos + 12)
        pos += 14
    else:
        help_id = None
        style = _dword(blob, pos)
        ex_style = _dword(blob, pos + 4)
        item_count = _word(blob, pos + 8)
        pos += 10
    x, y, cx, cy = (_short(blob, pos + 2 * i) for i in range(4))
    pos += 8
    rect = [x, y, cx, cy]

    menu_value, pos = _read_sz_or_ord(blob, pos, "menu")
    class_value, pos = _read_sz_or_ord(blob, pos, "class")
    title, pos = _read_utf16_z(blob, pos, "title")

    font: dict[str, Any] | None = None
    if style & DS_SETFONT:
        if ex_form:
            if pos + 6 > len(blob):
                raise AnalysisError(
                    f"truncated dialog template at offset 0x{pos:x}: EX font block incomplete"
                )
            font = {
                "point_size": _word(blob, pos),
                "weight": _word(blob, pos + 2),
                "italic": blob[pos + 4],
                "charset": blob[pos + 5],
            }
            pos += 6
        else:
            font = {"point_size": _word(blob, pos)}
            pos += 2
        typeface, pos = _read_utf16_z(blob, pos, "typeface")
        font["typeface"] = typeface

    items: list[dict[str, Any]] = []
    declared = item_count
    items_truncated = False
    for index in range(min(declared, MAX_ITEMS_PER_DIALOG)):
        pos = _align4(pos)
        _require_dialog_item_bytes(blob, pos, index, declared, ex_form)
        if ex_form:
            item_help: int | None = _dword(blob, pos)
            item_ex = _dword(blob, pos + 4)
            item_style = _dword(blob, pos + 8)
            ix, iy, icx, icy = (_short(blob, pos + 12 + 2 * i) for i in range(4))
            item_id = _dword(blob, pos + 20)
            pos += 24
        else:
            item_help = None
            item_style = _dword(blob, pos)
            item_ex = _dword(blob, pos + 4)
            ix, iy, icx, icy = (_short(blob, pos + 8 + 2 * i) for i in range(4))
            item_id = _word(blob, pos + 16)
            pos += 18
        item_class_value, pos = _read_sz_or_ord(blob, pos, "item class")
        item_title, pos = _read_sz_or_ord(blob, pos, "item title")
        extra = _word(blob, pos)
        pos += 2
        if pos + extra > len(blob):
            raise AnalysisError(
                f"truncated dialog template at offset 0x{pos:x}: item {index + 1} extra "
                f"data ({extra} bytes) runs past the resource end"
            )
        pos += extra
        items.append(
            {
                "id": item_id,
                "class": _class_label(item_class_value),
                "class_ordinal": item_class_value if isinstance(item_class_value, int) else None,
                "title": item_title or "",
                "style": item_style,
                "ex_style": item_ex,
                "help_id": item_help,
                "rect_dlu": [ix, iy, icx, icy],
                "rect_px": _dlu_to_px([ix, iy, icx, icy]),
            }
        )
    if declared > MAX_ITEMS_PER_DIALOG:
        items_truncated = True
        warnings.append(
            f"dialog '{name}': items bounded at {MAX_ITEMS_PER_DIALOG} "
            f"(template declares {declared})"
        )

    return {
        "name": name,
        "form": "ex" if ex_form else "classic",
        "help_id": help_id,
        "style": style,
        "ex_style": ex_style,
        "title": title,
        "class": _class_label(class_value),
        "menu": menu_value,
        "font": font,
        "rect_dlu": rect,
        "rect_px": _dlu_to_px(rect),
        "item_count": declared,
        "items_decoded": len(items),
        "items_truncated": items_truncated,
        "items": items,
    }


def _require_dialog_item_bytes(
    blob: bytes, pos: int, index: int, declared: int, ex_form: bool
) -> None:
    """Fail with a typed error when the bytes cannot hold item ``index``.

    This is the item-count-mismatch guard: the template declares ``declared``
    items and this one starts at ``pos``; anything short of the fixed item
    header means the template is truncated mid-item.
    """
    need = 22 if ex_form else 18
    if pos + need > len(blob):
        raise AnalysisError(
            f"truncated dialog template at offset 0x{pos:x}: item {index + 1} of "
            f"{declared} incomplete (declared {declared} items but the payload ends here)"
        )


# ---- menus -------------------------------------------------------------------


def _decode_menu(blob: bytes, name: str, warnings: list[str]) -> dict[str, Any]:
    """Decode one ``MENUTEMPLATE`` (classic) or ``MENUEX`` blob into an item tree."""
    version = _word(blob, 0)
    offset = _word(blob, 2)
    if version == 1 and offset == 4:
        kind = "menuex"
        budget = [0]
        items, _end = _menuex_level(blob, 8, budget, warnings, name)
    else:
        if version not in (0, 1):
            raise AnalysisError(f"unknown menu template version {version} in '{name}'")
        kind = "classic"
        budget = [0]
        start = max(offset, 4)  # header is 4 bytes; offset points at the first item
        items, _end = _menu_classic_level(blob, start, budget, warnings, name)
    total = budget[0]
    truncated = total >= MAX_MENU_ITEMS
    if truncated:
        warnings.append(f"menu '{name}': items bounded at {MAX_MENU_ITEMS}")
    return {
        "name": name,
        "kind": kind,
        "version": version,
        "item_count": total,
        "items_truncated": truncated,
        "items": items,
    }


def _menu_classic_level(
    blob: bytes, pos: int, budget: list[int], warnings: list[str], name: str
) -> tuple[list[dict[str, Any]], int]:
    """Walk one level of classic ``MENUITEMTEMPLATE`` entries until ``MF_END``.

    Real compiler output marks ``MF_END`` on the last item of the whole menu,
    so after a child list ends, a parent level stops cleanly when the blob is
    consumed; only bytes missing *mid-item* are a typed error.
    """
    entries: list[dict[str, Any]] = []
    while True:
        if budget[0] >= MAX_MENU_ITEMS:
            warnings.append(f"menu '{name}': item walk bounded at {MAX_MENU_ITEMS}")
            return entries, pos
        if pos + 2 > len(blob):
            return entries, pos  # end of data: the deepest MF_END propagated up
        option = _word(blob, pos)
        if option & MF_POPUP:
            text, pos = _read_utf16_z(blob, pos + 2, "menu popup")
            budget[0] += 1
            children, pos = _menu_classic_level(blob, pos, budget, warnings, name)
            entries.append({"id": None, "text": text, "popup": True, "children": children})
            if option & MF_END:
                return entries, pos
        else:
            item_id = _word(blob, pos + 2)
            text, pos = _read_utf16_z(blob, pos + 4, "menu item")
            budget[0] += 1
            entries.append({"id": item_id, "text": text, "popup": False, "children": []})
            if option & MF_END:
                return entries, pos


def _menuex_level(
    blob: bytes, pos: int, budget: list[int], warnings: list[str], name: str
) -> tuple[list[dict[str, Any]], int]:
    """Walk one level of ``MENUEX_TEMPLATE_ITEM`` entries until the end bit."""
    entries: list[dict[str, Any]] = []
    while True:
        if budget[0] >= MAX_MENU_ITEMS:
            warnings.append(f"menu '{name}': item walk bounded at {MAX_MENU_ITEMS}")
            return entries, pos
        if pos + 14 > len(blob):
            raise AnalysisError(
                f"truncated menu template at offset 0x{pos:x}: MENUEX item header incomplete"
            )
        dw_type = _dword(blob, pos)
        _dw_state = _dword(blob, pos + 4)
        item_id = _dword(blob, pos + 8)
        res_info = _word(blob, pos + 12)
        text, after_text = _read_utf16_z(blob, pos + 14, "menu item")
        pos = _align4(after_text)
        is_popup = bool(res_info & MENUEX_POPUP)
        budget[0] += 1
        children: list[dict[str, Any]] = []
        if is_popup:
            if pos + 4 > len(blob):
                raise AnalysisError(
                    f"truncated menu template at offset 0x{pos:x}: popup help id missing"
                )
            pos += 4  # dwHelpId of the popup header
            children, pos = _menuex_level(blob, pos, budget, warnings, name)
        entries.append(
            {
                "id": item_id,
                "text": text,
                "popup": is_popup,
                "type": dw_type,
                "children": children,
            }
        )
        if res_info & MENUEX_END:
            return entries, pos


# ---- string tables -----------------------------------------------------------


def _decode_string_block(
    blob: bytes, block_id: int, warnings: list[str]
) -> list[dict[str, Any]]:
    """Decode one ``RT_STRING`` block: 16 ``WORD``-length UTF-16 slots."""
    entries: list[dict[str, Any]] = []
    pos = 0
    for index in range(16):
        if pos + 2 > len(blob):
            break  # trailing empty slots may be omitted; a short block is not fatal
        length = _word(blob, pos)
        pos += 2
        kept = min(length, MAX_STRING_CHARS)
        if length > MAX_STRING_CHARS:
            warnings.append(
                f"string id {(block_id - 1) * 16 + index + 1}: capped at "
                f"{MAX_STRING_CHARS} of {length} chars"
            )
        if pos + 2 * length > len(blob):
            raise AnalysisError(
                f"malformed string table block {block_id}: string {index} claims {length} "
                f"chars but only {max(len(blob) - pos, 0)} bytes remain"
            )
        text = blob[pos : pos + 2 * kept].decode("utf-16-le", errors="replace")
        pos += 2 * length
        if text:
            # Slot numbers are 1-based in this project's convention: block 1
            # carries ids 1..16, block 2 ids 17..32 ((block - 1) * 16 + slot).
            entries.append({"id": (block_id - 1) * 16 + index + 1, "text": text})
    return entries


# ---- blob fetching (pe_resources directory data, without touching that module) --


def _fetch_blob(data: bytes, image: Any, leaf: _Leaf, warnings: list[str]) -> bytes | None:
    """Slice one leaf's payload out of the file bytes (bounded, never raises)."""
    offset = _rva_to_offset(image, leaf.data_rva)
    if offset is None or offset >= len(data):
        warnings.append(
            f"resource '{leaf.name}' payload RVA 0x{leaf.data_rva:x} is not mapped "
            "to file bytes; skipped"
        )
        return None
    end = min(offset + leaf.size, len(data))
    if end - offset != leaf.size:
        warnings.append(
            f"resource '{leaf.name}' payload is truncated in the file "
            f"({end - offset} of {leaf.size} bytes present)"
        )
    return data[offset:end]


def _block_id(leaf: _Leaf) -> int:
    """String-table block id carried by the resource name (integer names)."""
    try:
        return int(leaf.name)
    except ValueError:
        return 1


# ---- summary + public API ----------------------------------------------------


@dataclass(frozen=True)
class WinResUiSummary:
    """Bounded, JSON-safe view of one PE's Win32 UI resources."""

    path: str
    resource_table_present: bool
    dialog_count: int
    dialogs: tuple[dict[str, Any], ...]
    dialogs_truncated: bool
    dialog_item_count: int
    menu_count: int
    menus: tuple[dict[str, Any], ...]
    menus_truncated: bool
    stringtable_block_count: int
    stringtable_entry_count: int
    stringtable_entries: tuple[dict[str, Any], ...]
    stringtable_truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "resource_table_present": self.resource_table_present,
            "dialog_count": self.dialog_count,
            "dialogs": [dict(dialog) for dialog in self.dialogs],
            "dialogs_truncated": self.dialogs_truncated,
            "dialog_item_count": self.dialog_item_count,
            "menu_count": self.menu_count,
            "menus": [dict(menu) for menu in self.menus],
            "menus_truncated": self.menus_truncated,
            "stringtable_block_count": self.stringtable_block_count,
            "stringtable_entry_count": self.stringtable_entry_count,
            "stringtable_entries": [dict(entry) for entry in self.stringtable_entries],
            "stringtable_truncated": self.stringtable_truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _absent_summary(target: Path, warnings: list[str]) -> WinResUiSummary:
    return WinResUiSummary(
        path=str(target),
        resource_table_present=False,
        dialog_count=0,
        dialogs=(),
        dialogs_truncated=False,
        dialog_item_count=0,
        menu_count=0,
        menus=(),
        menus_truncated=False,
        stringtable_block_count=0,
        stringtable_entry_count=0,
        stringtable_entries=(),
        stringtable_truncated=False,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="data-directory-2-empty",
            confidence=Confidence.HIGH,
            detail="PE has no resource data directory: no UI resources to decode",
        ),
    )


def decode_ui_resources(path: str | Path) -> WinResUiSummary:
    """Decode the dialogs, menus and string tables of one PE (pure Python).

    Raises:
        AnalysisError: When the file is missing, not a PE, or one of the UI
            resource payloads is malformed (truncated template, unknown
            signature, item count mismatch, malformed string table). A PE
            without UI resources yields a valid empty summary.
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

    warnings: list[str] = []
    image = _parse_pe_image(data)
    present = len(image.directories) > 2 and image.directories[2] != (0, 0)
    if not present:
        return _absent_summary(target, warnings)
    dir_rva = image.directories[2][0]
    root_off = _rva_to_offset(image, dir_rva)
    if root_off is None:
        return _absent_summary(target, warnings)

    collector: list[_Leaf] = []
    budget = {"dirs": MAX_DIRECTORIES}
    _walk_directory(data, root_off, root_off, budget, collector, -1, "", "", -1, 0)

    dialog_leaves = [leaf for leaf in collector if leaf.type_id == 5]
    menu_leaves = [leaf for leaf in collector if leaf.type_id == 4]
    string_leaves = [leaf for leaf in collector if leaf.type_id == 6]

    dialogs: list[dict[str, Any]] = []
    for leaf in dialog_leaves[:MAX_DIALOGS]:
        blob = _fetch_blob(data, image, leaf, warnings)
        if blob:
            dialogs.append(_decode_dialog(blob, leaf.name, warnings))
    menus: list[dict[str, Any]] = []
    for leaf in menu_leaves[:MAX_DIALOGS]:
        blob = _fetch_blob(data, image, leaf, warnings)
        if blob:
            menus.append(_decode_menu(blob, leaf.name, warnings))
    entries: list[dict[str, Any]] = []
    for leaf in string_leaves:
        blob = _fetch_blob(data, image, leaf, warnings)
        if blob is not None:
            entries.extend(_decode_string_block(blob, _block_id(leaf), warnings))
    entries.sort(key=lambda entry: entry["id"])
    entry_count = len(entries)
    entries_kept = entries[:MAX_STRINGTABLE_ENTRIES]

    total_items = sum(dialog["items_decoded"] for dialog in dialogs)
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="winres-ui-decode",
        confidence=Confidence.HIGH,
        detail=(
            f"{len(dialog_leaves)} dialog(s), {len(menu_leaves)} menu(s), "
            f"{len(string_leaves)} string block(s), {total_items} dialog item(s)"
        ),
        extra={"root_rva": dir_rva, "leaf_count": len(collector)},
    )
    return WinResUiSummary(
        path=str(target),
        resource_table_present=True,
        dialog_count=len(dialog_leaves),
        dialogs=tuple(dialogs),
        dialogs_truncated=len(dialog_leaves) > MAX_DIALOGS,
        dialog_item_count=total_items,
        menu_count=len(menu_leaves),
        menus=tuple(menus),
        menus_truncated=len(menu_leaves) > MAX_DIALOGS,
        stringtable_block_count=len(string_leaves),
        stringtable_entry_count=entry_count,
        stringtable_entries=tuple(entries_kept),
        stringtable_truncated=entry_count > MAX_STRINGTABLE_ENTRIES,
        warnings=tuple(warnings),
        evidence=evidence,
    )


# ---- deterministic HTML preview ------------------------------------------------


def render_preview_html(summary: WinResUiSummary, title: str = "UI preview") -> str:
    """Render one summary as a deterministic, self-contained HTML page.

    Pure function of ``summary`` and ``title``: no timestamps, no random ids,
    stable ordering -- identical evidence produces byte-identical HTML. Pixel
    rects use the documented DLU approximation (4 px per x-DLU, 8 px per
    y-DLU) and every dialog item carries its ``data-id``.
    """
    esc = html.escape
    parts: list[str] = [
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n",
        f"<title>{esc(title)}</title>\n",
        _PREVIEW_CSS,
        "</head>\n<body>\n",
        f"<h1>{esc(title)}</h1>\n",
        "<p class=\"summary\">"
        f"{summary.dialog_count} dialog(s), {summary.menu_count} menu(s), "
        f"{summary.stringtable_entry_count} string(s). Pixel rects approximate "
        "DLUs (4 px per x-DLU, 8 px per y-DLU).</p>\n",
    ]
    if summary.warnings:
        parts.append("<p class=\"warnings\">warnings: ")
        parts.append(esc("; ".join(summary.warnings)))
        parts.append("</p>\n")
    for index, dialog in enumerate(summary.dialogs):
        width, height = dialog["rect_px"][2], dialog["rect_px"][3]
        heading = dialog["title"] or f"(unnamed {dialog['name']})"
        parts.append(
            f"<div class=\"dialog\" id=\"dialog-{index}\" "
            f"data-name=\"{esc(str(dialog['name']))}\" "
            f"style=\"width:{width}px;height:{height}px\">\n"
        )
        parts.append(f"<span class=\"dialog-title\">{esc(heading)}</span>\n")
        for item in dialog["items"]:
            css_class = str(item["class"] or "control").lower()
            label = item["title"] or str(item["class"] or "?")
            left, top, w, h = item["rect_px"]
            parts.append(
                f"<div class=\"item {css_class}\" data-id=\"{item['id']}\" "
                f"data-class=\"{esc(str(item['class'] or '?'))}\" "
                f"style=\"left:{left}px;top:{top}px;width:{w}px;height:{h}px\">"
                f"{esc(label)}</div>\n"
            )
        parts.append("</div>\n")

    parts.append(
        f"<details class=\"menus\"><summary>Menus ({summary.menu_count})</summary>\n"
    )
    for menu in summary.menus:
        parts.append(f"<p><strong>{esc(str(menu['name']))}</strong> ({menu['kind']})</p>\n")
        parts.append(_menu_html(menu["items"]))
    parts.append("</details>\n")

    parts.append(
        "<details class=\"strings\">"
        f"<summary>String table ({summary.stringtable_entry_count})</summary>\n"
        "<table>\n<tr><th>id</th><th>text</th></tr>\n"
    )
    for entry in summary.stringtable_entries:
        parts.append(f"<tr><td>{entry['id']}</td><td>{esc(entry['text'])}</td></tr>\n")
    parts.append("</table>\n</details>\n")
    parts.append("</body>\n</html>\n")
    return "".join(parts)


def _menu_html(items: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> str:
    """Render a decoded menu tree as nested lists (deterministic order)."""
    esc = html.escape
    lines = ["<ul>\n"]
    for item in items:
        label = esc(str(item["text"]))
        suffix = "" if item["id"] is None else f" <small>id={item['id']}</small>"
        if item["children"]:
            lines.append(f"<li>{label}{suffix}\n{_menu_html(item['children'])}</li>\n")
        else:
            lines.append(f"<li>{label}{suffix}</li>\n")
    lines.append("</ul>\n")
    return "".join(lines)


def layout_json_bytes(summary: WinResUiSummary) -> bytes:
    """Stable ``ui_layout.json`` companion bytes for one summary."""
    return json.dumps(summary.to_dict(), indent=2, sort_keys=True).encode("utf-8") + b"\n"

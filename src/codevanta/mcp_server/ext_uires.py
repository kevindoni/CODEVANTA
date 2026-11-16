"""MCP tools for the lane-uistatic (no MCP imports).

Two tools: ``codevanta_dialog_decode`` (decode the Win32 dialog/menu/string
resources of a PE into a bounded structured summary) and
``codevanta_ui_preview`` (render the same evidence into a deterministic HTML
preview plus a ``ui_layout.json`` companion on disk). The registration imports
live in :mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live
inside :func:`codevanta.mcp_server.server.build_server` -- imports alone do
not register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import winres_ui

TOOL_DESCRIPTION_DIALOG_DECODE = (
    "Decode the Win32 UI resources of a PE fully offline and pure Python: "
    "DLGTEMPLATE/DLGTEMPLATEEX dialog templates become a bounded widget tree "
    "(class, title, control id, style, DLU rect plus an honest pixel "
    "approximation of 4 px per x-DLU and 8 px per y-DLU), RT_MENU templates "
    "(classic MENUTEMPLATE and MENUEX) become an item tree with ids and text, "
    "and RT_STRING blocks yield their effective string ids ((block-1)*16+index). "
    "Bounds are reported honestly (64 dialogs, 256 items each, 256 menu items, "
    "512 strings); malformed templates are typed errors; a PE without UI "
    "resources is a valid empty result. Nothing is executed."
)

TOOL_DESCRIPTION_UI_PREVIEW = (
    "Render the Win32 UI resources of a PE as a deterministic HTML preview "
    "written to <output_directory>/ui_preview.html, plus a ui_layout.json "
    "companion with the full structured decode. The HTML places every dialog "
    "item as an absolutely-positioned div (pixel rects are the documented DLU "
    "approximation), carries data-id attributes, and nests the menu tree and "
    "string table in details blocks. Identical evidence produces "
    "byte-identical HTML (no timestamps). Pure stdlib rendering; nothing is "
    "executed."
)


def codevanta_dialog_decode(path: str) -> dict[str, Any]:
    """Decode one PE's dialogs, menus and string tables into a summary dict."""
    return winres_ui.decode_ui_resources(path).to_dict()


def codevanta_ui_preview(
    path: str,
    output_directory: str,
    assets_manifest_path: str | None = None,
) -> dict[str, Any]:
    """Write the deterministic HTML preview and layout JSON for one PE.

    With ``assets_manifest_path`` (a ``codevanta_pe_assets`` manifest JSON),
    every ``SS_ICON`` static is matched against the extracted icon assets and
    embedded as a ``data:image/png;base64`` URI (bounded 32 images, each at
    most 64 KiB, sha256-verified); unmatched or oversized statics keep their
    placeholder box and are counted honestly in the result.
    """
    summary = winres_ui.decode_ui_resources(path)
    out_dir = Path(output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    icon_plan = None
    assets_section: dict[str, Any] | None = None
    if assets_manifest_path:
        manifest = winres_ui.load_assets_manifest(assets_manifest_path)
        icon_plan = winres_ui.plan_icon_embeds(summary, manifest)
        assets_section = {
            "embedded": int(icon_plan.get("embedded", 0)),
            "skipped": int(icon_plan.get("skipped", 0)),
            "skipped_reasons": list(icon_plan.get("skipped_reasons", ())),
        }
    html_path = out_dir / "ui_preview.html"
    layout_path = out_dir / "ui_layout.json"
    html_text = winres_ui.render_preview_html(
        summary, title=f"UI preview: {Path(path).name}", icon_plan=icon_plan
    )
    layout_bytes = winres_ui.layout_json_bytes(summary)
    html_path.write_text(html_text, encoding="utf-8")
    layout_path.write_bytes(layout_bytes)
    files = [
        {"path": str(html_path), "bytes": len(html_text.encode("utf-8"))},
        {"path": str(layout_path), "bytes": len(layout_bytes)},
    ]
    result: dict[str, Any] = {
        "output_directory": str(out_dir),
        "files": files,
        "dialog_count": summary.dialog_count,
        "dialog_item_count": summary.dialog_item_count,
        "menu_count": summary.menu_count,
        "stringtable_entry_count": summary.stringtable_entry_count,
        "warnings": list(summary.warnings),
        "evidence": summary.evidence.to_dict(),
    }
    if assets_section is not None:
        result["assets"] = assets_section
    return result

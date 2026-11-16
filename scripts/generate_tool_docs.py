"""Generate ``docs/mcp-tools.md`` from the live MCP tool registry.

The reference is built by importing :func:`codevanta.mcp_server.build_server`
and listing the tools the server actually registers -- name, description and
input schema. It is never hand-maintained, so a tool added, renamed, or
re-described in ``src/codevanta/mcp_server/`` shows up as a documentation
change instead of silent drift.

Usage::

    python scripts/generate_tool_docs.py
    python scripts/generate_tool_docs.py --check
    python scripts/generate_tool_docs.py --date 2026-11-16 --output docs/mcp-tools.md

``--check`` writes nothing and exits 1 when the checked-in file differs from
what this run would generate. Wire it into ``.github/workflows/ci.yml`` as a
step in the ``test (py${{ matrix.python-version }})`` job, after ``Lint``::

    - name: MCP docs are current
      run: python scripts/generate_tool_docs.py --check

It needs no extra dependencies beyond the project itself (stdlib only), so no
install step changes are required. The generated date defaults to a fixed
constant -- not ``date.today()`` -- so re-running the generator is byte-for-byte
idempotent; pass ``--date`` to stamp a new one deliberately.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUTPUT = ROOT / "docs" / "mcp-tools.md"

#: Stable default for the "generated on" note. ``--date`` overrides it.
DEFAULT_DATE = "2026-11-16"

#: Display order of the category sections. Membership is mapped explicitly in
#: ``TOOLS_BY_CATEGORY`` so a new tool cannot silently change its category by
#: matching a fragile name pattern; it lands in ``Other`` until mapped.
CATEGORY_ORDER: tuple[str, ...] = (
    "Core analysis",
    "Static analysis",
    "Dynamic and debug",
    "Platform and mobile",
    "Web and JavaScript",
    "Firmware, hardware and network",
    "Formats and files",
    "Rebuild",
    "Sessions and navigation",
)

#: Tool names without the ``codevanta_`` prefix, grouped by category.
TOOLS_BY_CATEGORY: dict[str, frozenset[str]] = {
    "Core analysis": frozenset(
        {
            "info",
            "functions",
            "strings",
            "disasm",
            "analyze",
            "entropy",
            "xrefs",
            "cfg",
            "decompile",
            "callgraph",
            "diff",
            "jump_table",
            "function_hash",
            "similarity",
            "struct",
        }
    ),
    "Static analysis": frozenset(
        {
            "dataflow",
            "symbolic",
            "symbolic_solve",
            "emulate",
            "stackstrings",
            "ssa",
            "pseudo_c",
            "types",
            "demangle",
            "dwarf",
            "vtable",
            "compare",
            "unknowns",
            "obligations",
            "coverage",
            "call_path",
            "navigate",
            "graph_subset",
            "search_bytes",
            "search_strings",
            "search_procs",
            "capabilities",
            "capability_profile",
            "yara",
            "triage",
            "sbom",
            "rizin_functions",
            "gosymbols",
            "providers",
            "bridges",
        }
    ),
    "Dynamic and debug": frozenset(
        {
            "trace",
            "debug",
            "debug_start",
            "debug_status",
            "debug_close",
            "debug_sessions",
            "lldb_run",
            "frida",
            "frida_start",
            "frida_load",
            "frida_status",
            "frida_close",
            "frida_sessions",
            "proc_run",
            "proc_status",
            "proc_compare",
            "proc_sessions",
        }
    ),
    "Platform and mobile": frozenset(
        {
            "adb",
            "apk_decode",
            "dex",
            "il2cpp",
            "macho_symbols",
            "codesign",
            "pe_assets",
            "dialog_decode",
            "ui_preview",
            "win_windows",
            "win_tree",
            "win_shot",
            "win_click",
            "win_type",
            "win_key",
            "win_visual_regression",
        }
    ),
    "Web and JavaScript": frozenset(
        {
            "javascript",
            "electron_audit",
            "asar",
            "web_inspect",
            "web_capture",
            "replay_fixture",
            "sourcemap",
            "js_recover",
            "unpack",
            "wasm",
        }
    ),
    "Firmware, hardware and network": frozenset(
        {
            "signal_sr",
            "uart_decode",
            "dtb",
            "firmware_extract",
            "pcap_fields",
            "net_interfaces",
            "net_capture",
        }
    ),
    "Formats and files": frozenset(
        {
            "metadata",
            "crash",
            "binmeta",
            "sqlite",
            "proto_decode",
            "gpu",
            "pe_deep",
            "elf_macho",
            "containers",
            "png_diff",
            "fs_snapshot",
            "fs_diff",
            "rich",
            "delayload",
            "bplist",
            "pdb",
            "certs",
        }
    ),
    "Rebuild": frozenset(
        {
            "rebuild",
            "rebuild_build",
            "rebuild_build_auto",
            "rebuild_improve",
            "rebuild_list",
            "rebuild_show",
            "rebuild_check",
            "rebuild_check_behavior",
            "rebuild_ready",
            "rebuild_generate",
        }
    ),
    "Sessions and navigation": frozenset(
        {"session_save", "session_list", "nav", "nav_providers"}
    ),
}


def _category_index() -> dict[str, str]:
    """Map a short tool name to its category, rejecting duplicate mappings."""
    index: dict[str, str] = {}
    for category, names in TOOLS_BY_CATEGORY.items():
        if category not in CATEGORY_ORDER:
            raise RuntimeError(f"category {category!r} is not in CATEGORY_ORDER")
        for name in names:
            if name in index:
                raise RuntimeError(f"tool {name!r} is mapped to two categories")
            index[name] = category
    return index


def _load_tools() -> list[Any]:
    """Build the real server and return its public tool list."""
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from codevanta.mcp_server import build_server

    return asyncio.run(build_server().list_tools())


def _type_label(schema: dict[str, Any]) -> str:
    """Render a JSON-schema fragment as a short type label."""
    if "enum" in schema:
        values = ", ".join(str(value) for value in schema["enum"])
        return f"enum({values})"
    if "anyOf" in schema:
        labels: list[str] = []
        for part in schema["anyOf"]:
            label = _type_label(part)
            if label not in labels:
                labels.append(label)
        return " or ".join(labels)
    kind = schema.get("type")
    if kind == "array":
        return f"array<{_type_label(schema.get('items') or {})}>"
    if isinstance(kind, list):
        return " or ".join(str(item) for item in kind)
    return str(kind) if kind else "any"


def _parameters_cell(schema: dict[str, Any]) -> str:
    """Render the tool's input schema as one markdown-table cell."""
    properties = schema.get("properties") or {}
    if not properties:
        return "—"
    required = set(schema.get("required") or [])
    parts: list[str] = []
    for name, spec in properties.items():
        optional = name not in required
        label = f"{name}{'?' if optional else ''}: {_type_label(spec)}"
        if optional and spec.get("default") is not None:
            default = json.dumps(spec["default"], ensure_ascii=False)
            label += f" = {default}"
        parts.append(_cell(f"`{label}`"))
    return "<br>".join(parts)


def _cell(text: str) -> str:
    """Flatten a cell and escape table-breaking markdown/HTML characters."""
    flat = " ".join(text.split())
    flat = flat.replace("<", "&lt;").replace(">", "&gt;")
    return flat.replace("|", "\\|")


def _anchor(title: str) -> str:
    """GitHub-style heading anchor for a category title."""
    return title.lower().replace(",", "").replace(" ", "-")


def _group(tools: list[Any]) -> dict[str, list[Any]]:
    """Group tools by category, sorted by name, with an ``Other`` fallback."""
    index = _category_index()
    grouped: dict[str, list[Any]] = {category: [] for category in CATEGORY_ORDER}
    other: list[Any] = []
    for tool in sorted(tools, key=lambda item: item.name):
        short_name = tool.name.removeprefix("codevanta_")
        category = index.get(short_name)
        if category is None:
            other.append(tool)
        else:
            grouped[category].append(tool)
    if other:
        grouped["Other"] = other
    return {category: items for category, items in grouped.items() if items}


def render(tools: list[Any], generated_on: str) -> str:
    """Render the complete markdown document without touching the filesystem."""
    grouped = _group(tools)
    total = sum(len(items) for items in grouped.values())
    lines: list[str] = [
        "# MCP tool reference",
        "",
        "<!-- Generated by scripts/generate_tool_docs.py. Do not edit by hand. -->",
        "",
        f"Generated on **{generated_on}** from the live registry in",
        "`codevanta.mcp_server.build_server()`, which registers "
        f"**{total} tools** in {len(grouped)} categories.",
        "",
        "Regenerate with `python scripts/generate_tool_docs.py`; "
        "`--check` exits non-zero",
        "when this file is stale, so CI catches a registry change that was not",
        "documented. In the tables, a required argument has no suffix, `?` marks an",
        "optional one, and `= value` is its default.",
        "",
        "## Summary",
        "",
        "| Category | Tools |",
        "| --- | ---: |",
    ]
    for category, items in grouped.items():
        lines.append(f"| [{category}](#{_anchor(category)}) | {len(items)} |")
    lines += [f"| **Total** | **{total}** |", ""]

    for category, items in grouped.items():
        lines += [
            f"## {category}",
            "",
            "| Tool | Parameters | What it does |",
            "| --- | --- | --- |",
        ]
        for tool in items:
            description = _cell(tool.description or "(no description)")
            parameters = _parameters_cell(tool.input_schema or {})
            lines.append(f"| `{tool.name}` | {parameters} | {description} |")
        lines.append("")

    return "\n".join(lines)


def _display(path: Path) -> str:
    """Show repository-relative paths in messages when possible."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate docs/mcp-tools.md from the live MCP tool registry.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="write nothing; exit 1 when the checked-in file is stale (CI mode)",
    )
    parser.add_argument(
        "--date",
        default=DEFAULT_DATE,
        metavar="YYYY-MM-DD",
        help=f"date stamped in the generated note (default: {DEFAULT_DATE}, fixed "
        "so repeated runs are idempotent)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT,
        metavar="PATH",
        help="destination file (default: docs/mcp-tools.md)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        date.fromisoformat(args.date)
    except ValueError:
        parser.error(f"--date must be an ISO date (YYYY-MM-DD), got {args.date!r}")

    tools = _load_tools()
    document = render(tools, args.date)
    output: Path = args.output
    expected = document.encode("utf-8")

    if args.check:
        if not output.exists():
            print(
                f"{_display(output)} is missing; run python scripts/generate_tool_docs.py",
                file=sys.stderr,
            )
            return 1
        if output.read_bytes().replace(b"\r\n", b"\n") != expected:
            print(
                f"{_display(output)} is stale; run python scripts/generate_tool_docs.py",
                file=sys.stderr,
            )
            return 1
        print(f"{_display(output)} is up to date ({len(tools)} tools)")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected)
    print(f"wrote {_display(output)} ({len(tools)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

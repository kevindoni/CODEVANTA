"""Generate docs/tool_audit.md -- an objective depth audit of every MCP tool.

Methodology:
- Tool names come from the pinned list in tests/test_mcp_tools.py.
- Backing module = the mcp_server/ext_*.py (or tools.py) file defining
  ``def codevanta_<tool>``; LOC counted from that file plus its largest
  ``codevanta.analysis`` import (the engine module).
- "runs external tool" = subprocess/Popen/shutil.which/frida/gdb/lldb in the
  backing module or engine.
- Category: HOST (live-process/input automation), BRIDGE (runs an external
  tool), else ANALYSIS. Depth by LOC: Deep >=400, Medium 150-399, Thin <150.
Temporary helper; regenerate with: python scripts/_gen_tool_audit.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests" / "test_mcp_tools.py"
SERVER_DIR = ROOT / "src" / "codevanta" / "mcp_server"
ANALYSIS_DIR = ROOT / "src" / "codevanta" / "analysis"
OUT = ROOT / "docs" / "tool_audit.md"

HOST_TOOLS = {
    "codevanta_win_click", "codevanta_win_type", "codevanta_win_key",
    "codevanta_win_visual_regression", "codevanta_proc_run",
    "codevanta_proc_compare", "codevanta_proc_sessions",
    "codevanta_proc_status", "codevanta_debug", "codevanta_debug_start",
    "codevanta_debug_close", "codevanta_debug_sessions",
    "codevanta_debug_status", "codevanta_frida", "codevanta_frida_start",
    "codevanta_frida_load", "codevanta_frida_close",
    "codevanta_frida_sessions", "codevanta_frida_status",
    "codevanta_lldb_run",
}

EXTERNAL_HINT = re.compile(r"subprocess|Popen|shutil\.which|os\.system|frida\b|gdb\b|lldb\b")
DEF_RE = re.compile(r"def (codevanta_[a-z0-9_]+)\(")
IMPORT_RE = re.compile(r"from codevanta\.analysis\.([a-z_]+) import")


def loc(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return 0


def shells_out(path: Path) -> bool:
    try:
        return bool(EXTERNAL_HINT.search(path.read_text(encoding="utf-8")))
    except OSError:
        return False


def main() -> None:
    test_text = TESTS.read_text(encoding="utf-8")
    names = sorted(set(re.findall(r'"(codevanta_[a-z0-9_]+)"', test_text)))

    tool_to_file: dict[str, Path] = {}
    for path in sorted(SERVER_DIR.glob("ext_*.py")) + [SERVER_DIR / "tools.py"]:
        for match in DEF_RE.finditer(path.read_text(encoding="utf-8")):
            tool_to_file.setdefault(match.group(1), path)
    # analyze is a tools.py wrapper whose engine lives in analysis/binmeta.py
    tool_to_file.setdefault("codevanta_analyze", ANALYSIS_DIR / "binmeta.py")

    rows = []
    engine_cache: dict[str, tuple[int, bool]] = {}
    for name in names:
        backing = tool_to_file.get(name)
        if backing is None:
            rows.append((name, "?", "?", 0))
            continue
        backing_text = backing.read_text(encoding="utf-8")
        total = loc(backing)
        external = shells_out(backing)
        engine, engine_size = "", 0
        for match in IMPORT_RE.finditer(backing_text):
            candidate = ANALYSIS_DIR / (match.group(1) + ".py")
            size = loc(candidate)
            if size > engine_size:
                engine, engine_size = candidate.stem, size
        if engine_size:
            total += engine_size
            if engine not in engine_cache:
                engine_cache[engine] = (engine_size, shells_out(ANALYSIS_DIR / (engine + ".py")))
            external = external or engine_cache[engine][1]
        category = "HOST" if name in HOST_TOOLS else ("BRIDGE" if external else "ANALYSIS")
        rows.append((name, category, engine or "(ext only)", total))

    deep = sum(1 for r in rows if r[3] >= 400)
    medium = sum(1 for r in rows if 150 <= r[3] < 400)
    thin = sum(1 for r in rows if r[3] < 150)
    counts = {"ANALYSIS": 0, "BRIDGE": 0, "HOST": 0}
    for r in rows:
        counts[r[1]] = counts.get(r[1], 0) + 1

    lines = [
        "# Tool depth audit (v0.5.0)",
        "",
        "Objective audit of all registered MCP tools, generated from the",
        "pinned tool list in `tests/test_mcp_tools.py` plus file metrics:",
        "LOC of the backing `ext_*.py` plus its largest `codevanta.analysis`",
        "engine module, and a subprocess/which/frida/gdb scan for external-",
        "tool usage. Depth is a size proxy, not a quality verdict; the",
        "per-tool quality signal remains its `tests/` coverage.",
        "",
        f"- Total tools: **{len(rows)}**",
        f"- Categories: **{counts['ANALYSIS']}** pure offline analysis,",
        f"  **{counts['BRIDGE']}** external-tool bridges, **{counts['HOST']}**",
        "  host-automation / live-process",
        f"- Depth by backing LOC: **{deep} deep** (>=400), {medium} medium",
        f"  (150-399), {thin} thin (<150)",
        "",
        "## All tools",
        "",
        "| tool | category | engine module | backing LOC | depth |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, category, engine, total in rows:
        depth = "Deep" if total >= 400 else ("Medium" if total >= 150 else "Thin")
        lines.append(f"| `{name}` | {category} | {engine} | {total} | {depth} |")

    lines += [
        "",
        "## Reading the numbers",
        "",
        "- **ANALYSIS** tools never leave the process: pure-Python engines",
        "  over bytes the loader already read (offline by construction).",
        "- **BRIDGE** tools shell out to an optional external tool (frida,",
        "  gdb/lldb, rizin, adb/apktool, tshark, ...); they degrade with a",
        "  typed error naming the missing binary when it is not installed.",
        "- **HOST** tools deliberately act on the live machine (SendInput",
        "  automation, process inspection, debugger/injection sessions).",
        "- Thin tools are intentionally small wrappers around one bounded",
        "  engine call, not incomplete engines.",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} with {len(rows)} tools")


if __name__ == "__main__":
    main()

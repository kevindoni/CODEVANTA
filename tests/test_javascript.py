"""Tests for the static JavaScript/Electron application analysis lane."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from codevanta.analysis.javascript import (
    MAX_FILE_BYTES,
    MAX_FILES,
    analyze_javascript_app,
    classify_spec,
)
from codevanta.cli.main import app as cli
from codevanta.core.report import AnalysisError
from codevanta.gui.server import ROUTES
from codevanta.mcp_server import tools as mcp_tools

runner = CliRunner()


# ---- fixtures ---------------------------------------------------------------


def _write(path: Path, relative: str, text: str) -> None:
    """Write one UTF-8 file under ``path``, creating parent directories."""
    target = path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


@pytest.fixture
def app_dir(tmp_path: Path) -> Path:
    """A small but realistic Electron-shaped application directory."""
    _write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "name": "demo-app",
                "main": "main.js",
                "devDependencies": {"electron": "33.2.0"},
            }
        ),
    )
    _write(
        tmp_path,
        "main.js",
        "\n".join(
            [
                "const { ipcMain, BrowserWindow } = require('electron');",
                "const util = require('./lib/util');",
                "const fs = require('fs');",
                "const _ = require('lodash');",
                "ipcMain.handle('config:load', (event, key) => key);",
            ]
        ),
    )
    _write(tmp_path, "lib/util.js", "export const noop = () => {};\n")
    _write(
        tmp_path,
        "lib/index.js",
        "export { noop } from './util';\n",
    )
    _write(
        tmp_path,
        "preload.js",
        "const { contextBridge } = require('electron');\n"
        "contextBridge.exposeInMainWorld('api', {});\n",
    )
    _write(
        tmp_path,
        "renderer.js",
        "const { ipcRenderer } = require('electron');\n"
        "const v = await ipcRenderer.invoke('config:load');\n"
        "ipcRenderer.send('telemetry:ping');\n",
    )
    _write(tmp_path, "node_modules/junk/index.js", "module.exports = {};\n")
    return tmp_path


# ---- ASAR fixture builder (same byte layout as test_web.py) ------------------


def _add_file(tree: dict[str, Any], name: str, attrs: dict[str, Any]) -> None:
    """Insert one file node into an ASAR header tree, creating directories."""
    node = tree["files"]
    for part in name.split("/")[:-1]:
        child = node.setdefault(part, {"files": {}})
        node = child["files"]
    node[name.rsplit("/", 1)[-1]] = attrs


def _build_asar(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Write an .asar byte-by-byte (pickle header, JSON tree, payload)."""
    path = tmp_path / "app.asar"
    json_text = "{}"
    for _ in range(8):
        tree: dict[str, Any] = {"files": {}}
        cursor = 0
        for fname, content in files.items():
            _add_file(
                tree,
                fname,
                {"size": str(len(content)), "offset": str(cursor)},
            )
            cursor += len(content)
        new_json = json.dumps(tree, separators=(",", ":"))
        if new_json == json_text:
            break
        json_text = new_json
    blob = (
        struct.pack("<II", 4, len(json_text))
        + json_text.encode("utf-8")
        + b"\x00" * (-len(json_text) % 4)
    )
    path.write_bytes(blob + b"".join(files.values()))
    return path


# ---- specifier classification ------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("./util", "relative"),
        ("../shared/x", "relative"),
        (".", "relative"),
        ("fs", "builtin"),
        ("node:fs/promises", "builtin"),
        ("lodash", "bare"),
        ("lodash/merge", "bare"),
        ("@scope/pkg/sub", "bare"),
    ],
)
def test_classify_spec_shapes(spec: str, expected: str) -> None:
    """Classification is name-shape only and covers the three kinds."""
    assert classify_spec(spec) == expected


# ---- directory scans ---------------------------------------------------------


def test_directory_scan_classifies_imports_roles_and_package(app_dir: Path) -> None:
    """Roles, import kinds, resolution and package facts all land in one report."""
    report = analyze_javascript_app(app_dir)
    payload = report.to_dict()

    assert payload["kind"] == "directory"
    assert payload["file_count"] == 5  # node_modules is pruned, never counted
    assert payload["skipped"]["directories"] == 1
    assert not payload["truncated"]

    package = payload["package"]
    assert package["name"] == "demo-app"
    assert package["main"] == "main.js"
    assert package["electron_version"] == "33.2.0"
    assert package["evidence"]["confidence"] == "certain"

    by_path = {f["path"]: f for f in payload["files"]}
    assert by_path["main.js"]["role"] == "main"
    assert by_path["preload.js"]["role"] == "preload"
    assert by_path["renderer.js"]["role"] == "renderer"
    assert by_path["lib/util.js"]["role"] == "unknown"
    assert by_path["main.js"]["role_confidence"] == "medium"
    assert set(by_path["main.js"]["role_markers"]) == {"ipcMain", "BrowserWindow"}

    main_imports = {(i["spec"], i["kind"], i["syntax"]) for i in by_path["main.js"]["imports"]}
    assert ("electron", "bare", "require") in main_imports
    assert ("fs", "builtin", "require") in main_imports
    assert ("lodash", "bare", "require") in main_imports
    relative = [i for i in by_path["main.js"]["imports"] if i["spec"] == "./lib/util"]
    assert relative and relative[0]["resolved"] == "lib/util.js"

    esm = {(i["spec"], i["syntax"]) for i in by_path["lib/index.js"]["imports"]}
    assert ("./util", "export-from") in esm
    resolved = [i for i in by_path["lib/index.js"]["imports"] if i["spec"] == "./util"]
    assert resolved and resolved[0]["resolved"] == "lib/util.js"

    assert payload["external_packages"] == {"electron": 3, "lodash": 1}
    assert payload["import_kinds"] == {"relative": 2, "bare": 4, "builtin": 1}
    assert payload["evidence"]["method"] == "bounded_walk"


def test_ipc_channels_paired_across_sides(app_dir: Path) -> None:
    """A shared channel string becomes one medium-confidence pair; unmatched
    channels stay on their own side instead of being invented."""
    report = analyze_javascript_app(app_dir)
    payload = report.to_dict()

    pairs = payload["ipc"]["pairs"]
    assert [p["channel"] for p in pairs] == ["config:load"]
    assert pairs[0]["evidence"]["confidence"] == "medium"
    assert pairs[0]["evidence"]["method"] == "channel_name_match"
    assert [s["api"] for s in pairs[0]["main"]] == ["ipcMain.handle"]
    assert [s["api"] for s in pairs[0]["renderer"]] == ["ipcRenderer.invoke"]

    assert [s["channel"] for s in payload["ipc"]["renderer_only"]] == ["telemetry:ping"]
    assert payload["ipc"]["main_only"] == []


def test_node_modules_pruned_but_counted(app_dir: Path) -> None:
    """Pruned directories never contribute files; the count says they existed."""
    payload = analyze_javascript_app(app_dir).to_dict()
    assert all(not f["path"].startswith("node_modules/") for f in payload["files"])
    assert payload["skipped"]["directories"] == 1


def test_large_file_skipped_with_warning(tmp_path: Path) -> None:
    """A file above the per-file cap is skipped, named and warned about."""
    _write(tmp_path, "huge.js", "// pad\n" + "x" * MAX_FILE_BYTES)
    payload = analyze_javascript_app(tmp_path).to_dict()
    assert payload["files_scanned"] == 0
    assert payload["skipped"]["large_files"] == 1
    assert any("huge.js" in w for w in payload["warnings"])
    assert any("no package.json" in w for w in payload["warnings"])


def test_max_files_truncates_with_honest_count(tmp_path: Path) -> None:
    """Rows stop at the cap while file_count keeps counting every JS file."""
    for index in range(5):
        _write(tmp_path, f"f{index}.js", f"// {index}\n")
    payload = analyze_javascript_app(tmp_path, max_files=2).to_dict()
    assert payload["files_scanned"] == 2
    assert payload["file_count"] == 5
    assert payload["truncated"]


def test_missing_package_json_and_invalid_json_only_warn(tmp_path: Path) -> None:
    """A missing root manifest warns; a broken one warns and keeps scanning."""
    _write(tmp_path, "package.json", "{ not json")
    _write(tmp_path, "a.js", "require('fs');\n")
    payload = analyze_javascript_app(tmp_path).to_dict()
    assert payload["package"] is None
    assert payload["files_scanned"] == 1
    assert any("package.json" in w for w in payload["warnings"])


def test_bad_utf8_file_skipped_with_warning(tmp_path: Path) -> None:
    """Non-UTF-8 source degrades to a warning for that file, not a crash."""
    (tmp_path / "binary.js").write_bytes(b"\xff\xfe\x00const = 1;\n")
    payload = analyze_javascript_app(tmp_path).to_dict()
    assert payload["files_scanned"] == 0
    assert payload["skipped"]["unreadable"] == 1
    assert any("binary.js" in w for w in payload["warnings"])


def test_typed_errors_for_bad_inputs(tmp_path: Path) -> None:
    """Missing paths, wrong kinds and bad caps raise typed errors."""
    with pytest.raises(AnalysisError, match="cannot stat"):
        analyze_javascript_app(tmp_path / "missing")
    plain = tmp_path / "notes.txt"
    plain.write_text("hi", encoding="utf-8")
    with pytest.raises(AnalysisError, match="neither a directory nor an .asar"):
        analyze_javascript_app(plain)
    with pytest.raises(AnalysisError, match="max_files"):
        analyze_javascript_app(tmp_path, max_files=0)
    with pytest.raises(AnalysisError, match="max_files"):
        analyze_javascript_app(tmp_path, max_files=MAX_FILES + 1)


# ---- ASAR scans ---------------------------------------------------------------


def test_asar_scan_reads_javascript_inside_the_archive(tmp_path: Path) -> None:
    """The archive lane finds the same facts without extracting to disk."""
    archive = _build_asar(
        tmp_path,
        {
            "package.json": b'{"name": "packed", "main": "main.js"}',
            "main.js": (
                b"const { ipcMain } = require('electron');\n"
                b"ipcMain.handle('cfg:get', () => 1);\n"
            ),
            "renderer.js": (
                b"const { ipcRenderer } = require('electron');\n"
                b"ipcRenderer.invoke('cfg:get');\n"
            ),
            "node_modules/skip/index.js": b"module.exports = 1;\n",
            "assets/logo.png": b"\x89PNG-not-really",
        },
    )
    payload = analyze_javascript_app(archive).to_dict()
    assert payload["kind"] == "asar"
    assert payload["file_count"] == 2  # node_modules pruned, .png not JavaScript
    assert payload["skipped"]["directories"] == 1
    assert payload["package"]["name"] == "packed"
    assert [p["channel"] for p in payload["ipc"]["pairs"]] == ["cfg:get"]
    assert payload["evidence"]["method"] == "asar_listing"


def test_asar_unpacked_entries_skipped_with_warning(tmp_path: Path) -> None:
    """Unpacked entries are refused by the asar parser and surface as skips."""
    archive = tmp_path / "app.asar"
    json_text = '{"files": {"main.js": {"size": "20", "offset": "0", "unpacked": true}}}'
    blob = (
        struct.pack("<II", 4, len(json_text))
        + json_text.encode()
        + b"\x00" * (-len(json_text) % 4)
    )
    archive.write_bytes(blob)
    payload = analyze_javascript_app(archive).to_dict()
    assert payload["skipped"]["unpacked"] == 1
    assert any("unpacked" in w for w in payload["warnings"])


# ---- MCP tool ------------------------------------------------------------------


def test_mcp_javascript_tool_reports_shape(app_dir: Path) -> None:
    """The MCP wrapper returns the same payload as the engine."""
    payload = mcp_tools.codevanta_javascript(str(app_dir))
    assert payload["kind"] == "directory"
    assert payload["package"]["name"] == "demo-app"
    assert [p["channel"] for p in payload["ipc"]["pairs"]] == ["config:load"]


def test_mcp_javascript_tool_rejects_bad_path_and_cap(tmp_path: Path) -> None:
    """Wrong kinds and out-of-range caps surface as typed errors."""
    plain = tmp_path / "x.txt"
    plain.write_text("hi", encoding="utf-8")
    with pytest.raises(AnalysisError, match="neither a directory nor an .asar"):
        mcp_tools.codevanta_javascript(str(plain))
    with pytest.raises(AnalysisError, match="max_files"):
        mcp_tools.codevanta_javascript(str(tmp_path), max_files=0)


# ---- GUI route ------------------------------------------------------------------


def test_gui_javascript_route_serves_the_payload(app_dir: Path) -> None:
    """/api/js is a thin adapter over the engine, bounds and all."""
    builder = ROUTES["/api/js"]
    payload = builder({"path": str(app_dir)}, True)
    assert payload["kind"] == "directory"
    assert payload["package"]["name"] == "demo-app"


# ---- CLI ------------------------------------------------------------------------


def test_cli_js_analyze_json(app_dir: Path) -> None:
    """`codevanta js analyze --json` prints the engine payload unchanged."""
    result = runner.invoke(cli, ["js", "analyze", str(app_dir), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["package"]["name"] == "demo-app"
    assert [p["channel"] for p in payload["ipc"]["pairs"]] == ["config:load"]


def test_cli_js_analyze_table_and_error_paths(tmp_path: Path) -> None:
    """The table renders and typed errors exit 2 with the engine message."""
    _write(tmp_path, "solo.js", "require('fs');\n")
    result = runner.invoke(cli, ["js", "analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "solo.js" in result.output

    missing = tmp_path / "nope"
    result = runner.invoke(cli, ["js", "analyze", str(missing)])
    assert result.exit_code == 2
    assert "cannot stat" in result.output

    result = runner.invoke(cli, ["js", "analyze", str(tmp_path), "--max-files", "0"])
    assert result.exit_code == 2
    assert "max_files" in result.output

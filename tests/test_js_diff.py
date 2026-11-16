"""Version diff between two JavaScript/Electron application inventories."""

from __future__ import annotations

import json
from pathlib import Path

from codevanta.analysis.js_diff import compare_js_apps


def _app(root: Path, main_js: str, package: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.js").write_text(main_js, encoding="utf-8")
    (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
    return root


V1_MAIN = (
    'const { ipcMain } = require("electron");\n'
    'const util = require("util");\n'
    'ipcMain.handle("sum", (e, a, b) => a + b);\n'
)
V2_MAIN = (
    'const { ipcMain } = require("electron");\n'
    'const os = require("os");\n'
    'ipcMain.handle("sum", (e, a, b) => a + b);\n'
    'ipcMain.handle("secret", (e) => 42);\n'
)


def test_diff_reports_modules_packages_and_ipc(tmp_path: Path) -> None:
    left = _app(
        tmp_path / "v1",
        V1_MAIN,
        {"name": "app", "main": "main.js", "dependencies": {"left-pad": "1.0.0"}},
    )
    right = _app(
        tmp_path / "v2",
        V2_MAIN,
        {
            "name": "app",
            "main": "main.js",
            "dependencies": {"left-pad": "1.3.1", "got": "11.0.0"},
        },
    )

    payload = compare_js_apps(left, right).to_dict()

    assert payload["identical"] is False
    changed = payload["files"]["changed"]
    assert len(changed) == 1 and changed[0]["path"] == "main.js"
    assert any("os" in imp for imp in changed[0]["imports_added"])
    assert any("util" in imp for imp in changed[0]["imports_removed"])
    packages = {(row["name"], row["kind"]) for row in payload["packages"]}
    assert ("left-pad", "version") in packages
    assert ("got", "added") in packages
    channels = {row["channel"] for row in payload["ipc"]}
    assert "secret" in channels


def test_identical_builds_report_no_delta(tmp_path: Path) -> None:
    left = _app(
        tmp_path / "a", V1_MAIN, {"name": "app", "main": "main.js", "dependencies": {}}
    )
    right = _app(
        tmp_path / "b", V1_MAIN, {"name": "app", "main": "main.js", "dependencies": {}}
    )

    payload = compare_js_apps(left, right).to_dict()

    assert payload["identical"] is True
    assert payload["evidence"]["confidence"] == "medium"


def test_added_and_removed_modules(tmp_path: Path) -> None:
    left = _app(tmp_path / "v1", V1_MAIN, {"name": "app"})
    (left / "gone.js").write_text('const x = require("x");\n', encoding="utf-8")
    right = _app(tmp_path / "v2", V1_MAIN, {"name": "app"})
    (right / "new.js").write_text('const y = require("y");\n', encoding="utf-8")

    payload = compare_js_apps(left, right).to_dict()

    assert [row["path"] for row in payload["files"]["removed"]] == ["gone.js"]
    assert [row["path"] for row in payload["files"]["added"]] == ["new.js"]


def test_channel_losing_its_renderer_side_is_flagged(tmp_path: Path) -> None:
    both = (
        'const { ipcMain } = require("electron");\n'
        'ipcMain.handle("cfg", () => 1);\n'
    )
    renderer = 'const { ipcRenderer } = require("electron");\nipcRenderer.invoke("cfg");\n'
    left = _app(tmp_path / "v1", both, {"name": "app"})
    (left / "renderer.js").write_text(renderer, encoding="utf-8")
    right = _app(tmp_path / "v2", both, {"name": "app"})

    payload = compare_js_apps(left, right).to_dict()

    rows = {row["channel"]: row for row in payload["ipc"]}
    assert rows["cfg"]["kind"] == "main_only"

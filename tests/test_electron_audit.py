"""Tests for the static Electron security audit lane."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from codevanta.analysis.electron_audit import (
    MAX_FILES,
    MAX_FINDINGS,
    MAX_FINDINGS_PER_FILE,
    audit_electron_app,
)
from codevanta.core.report import AnalysisError

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---- fixtures ---------------------------------------------------------------


def _write(path: Path, relative: str, text: str) -> None:
    """Write one UTF-8 file under ``path``, creating parent directories."""
    target = path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


@pytest.fixture
def vuln_app(tmp_path: Path) -> Path:
    """A deliberately vulnerable Electron application directory."""
    _write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "name": "vuln-app",
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
                "const { app, BrowserWindow, shell } = require('electron');",
                "const { exec } = require('child_process');",
                "function createWindow() {",
                "  const win = new BrowserWindow({",
                "    webPreferences: { nodeIntegration: true, contextIsolation: false,"
                " sandbox: false, webSecurity: false, allowRunningInsecureContent: true },",
                "  });",
                "  win.loadURL('https://example.com/app');",
                "  return win;",
                "}",
                "app.whenReady().then(createWindow);",
                "exec(`open ${target}`);",
                "shell.openExternal(link);",
            ]
        ),
    )
    _write(tmp_path, "index.html", "<!doctype html><html><body>no csp</body></html>\n")
    _write(tmp_path, "node_modules/junk/index.js", "module.exports = {};\n")
    return tmp_path


@pytest.fixture
def safe_app(tmp_path: Path) -> Path:
    """A hardened application: sane webPreferences, preload with literal
    channels, and a CSP meta tag."""
    _write(
        tmp_path,
        "package.json",
        json.dumps({"name": "safe-app", "main": "main.js"}),
    )
    _write(
        tmp_path,
        "main.js",
        "\n".join(
            [
                "const { app, BrowserWindow } = require('electron');",
                "const win = new BrowserWindow({",
                "  webPreferences: { nodeIntegration: false, contextIsolation: true,"
                " sandbox: true, webSecurity: true },",
                "});",
                "win.loadFile('index.html');",
                "app.whenReady().then(() => {});",
            ]
        ),
    )
    _write(
        tmp_path,
        "preload.js",
        "const { contextBridge, ipcRenderer } = require('electron');\n"
        "contextBridge.exposeInMainWorld('api', {\n"
        "  load: (key) => ipcRenderer.invoke('app:load', key),\n"
        "});\n",
    )
    _write(
        tmp_path,
        "index.html",
        "<!doctype html><html><head>\n"
        '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">\n'
        "</head><body>ok</body></html>\n",
    )
    return tmp_path


# ---- ASAR fixture builder (same byte layout as test_javascript.py) ----------


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


# ---- vulnerable application ---------------------------------------------------


def test_vulnerable_app_hits_every_rule_family(vuln_app: Path) -> None:
    """Each planted anti-pattern lands with its severity, line and evidence."""
    payload = audit_electron_app(vuln_app).to_dict()

    by_rule = {f["rule_id"]: f for f in payload["findings"]}
    assert set(by_rule) == {
        "EA-001", "EA-002", "EA-003", "EA-004", "EA-005",
        "EA-010", "EA-020", "EA-040", "EA-042",
    }
    assert by_rule["EA-001"]["severity"] == "critical"
    assert by_rule["EA-001"]["line"] == 5
    assert "nodeIntegration: true" in by_rule["EA-001"]["snippet"]
    assert by_rule["EA-001"]["evidence"]["source"] == "electron.audit"
    assert by_rule["EA-001"]["evidence"]["method"] == "regex_rule_scan"
    assert by_rule["EA-001"]["evidence"]["confidence"] == "certain"
    assert by_rule["EA-002"]["severity"] == "critical"
    assert by_rule["EA-003"]["severity"] == "high"
    assert by_rule["EA-004"]["severity"] == "high"
    assert by_rule["EA-005"]["severity"] == "medium"

    assert by_rule["EA-020"]["line"] == 11
    assert by_rule["EA-020"]["severity"] == "critical"
    assert by_rule["EA-020"]["confidence"] == "heuristic"
    assert by_rule["EA-020"]["evidence"]["confidence"] == "medium"

    assert by_rule["EA-040"]["line"] == 12
    assert by_rule["EA-040"]["severity"] == "high"

    assert by_rule["EA-042"]["line"] == 7
    assert by_rule["EA-042"]["severity"] == "medium"
    assert by_rule["EA-042"]["confidence"] == "high"
    assert by_rule["EA-042"]["evidence"]["extra"]["role"] == "main"

    assert by_rule["EA-010"]["file"] == "."
    assert by_rule["EA-010"]["line"] == 0
    assert by_rule["EA-010"]["snippet"] == ""
    assert by_rule["EA-010"]["evidence"]["method"] == "absence_check"

    assert payload["summary"] == {"critical": 3, "high": 4, "medium": 2, "low": 0, "info": 0}
    assert payload["scanned_files"] == 2  # main.js + index.html; node_modules pruned
    assert payload["file_count"] == 2
    assert payload["skipped"]["directories"] == 1
    assert not payload["truncated"]


def test_findings_sorted_by_severity_then_file_then_line(vuln_app: Path) -> None:
    """The findings tuple is deterministically ordered."""
    report = audit_electron_app(vuln_app)
    keys = [
        (_SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id) for f in report.findings
    ]
    assert keys == sorted(keys)


def test_payload_is_json_safe(vuln_app: Path) -> None:
    """The report payload survives a JSON round trip unchanged."""
    payload = audit_electron_app(vuln_app).to_dict()
    assert json.loads(json.dumps(payload)) == payload


def test_context_carries_js_inventory(vuln_app: Path) -> None:
    """Package facts and role counts from the inventory are embedded."""
    payload = audit_electron_app(vuln_app).to_dict()
    context = payload["context"]
    assert context["package"]["name"] == "vuln-app"
    assert context["package"]["electron_version"] == "33.2.0"
    assert context["role_counts"] == {"main": 1}
    assert context["js_file_count"] == 1


# ---- safe application ---------------------------------------------------------


def test_safe_app_yields_no_findings(safe_app: Path) -> None:
    """Hardened options, literal channels and a CSP produce zero findings."""
    payload = audit_electron_app(safe_app).to_dict()
    assert payload["findings"] == []
    assert payload["summary"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert not payload["truncated"]


def test_literal_shapes_are_not_flagged(tmp_path: Path) -> None:
    """Literal openExternal/execFile targets do not match; only the no-CSP
    heuristic remains."""
    _write(
        tmp_path,
        "main.js",
        "\n".join(
            [
                "const { shell } = require('electron');",
                "const { execFile } = require('child_process');",
                "shell.openExternal('https://example.com');",
                "execFile('ls', ['-la'], () => {});",
            ]
        ),
    )
    payload = audit_electron_app(tmp_path).to_dict()
    ids = {f["rule_id"] for f in payload["findings"]}
    assert ids == {"EA-010"}


# ---- CSP rules ----------------------------------------------------------------


def test_unsafe_csp_flagged_and_absence_suppressed(tmp_path: Path) -> None:
    """A shipped CSP suppresses EA-010 but unsafe-inline trips EA-011."""
    _write(
        tmp_path,
        "index.html",
        "<!doctype html>\n<html><head>\n"
        '<meta http-equiv="Content-Security-Policy"'
        " content=\"script-src 'self' 'unsafe-inline'\">\n"
        "</head><body>ok</body></html>\n",
    )
    _write(tmp_path, "app.js", "const { app } = require('electron');\n")
    payload = audit_electron_app(tmp_path).to_dict()

    ids = {f["rule_id"] for f in payload["findings"]}
    assert ids == {"EA-011"}
    finding = payload["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "heuristic"
    assert finding["evidence"]["confidence"] == "medium"
    assert finding["line"] == 3
    assert "unsafe-inline" in finding["snippet"]


def test_csp_header_in_javascript_counts_as_presence(tmp_path: Path) -> None:
    """An onHeadersReceived CSP header suppresses the absence finding."""
    _write(
        tmp_path,
        "main.js",
        "session.defaultSession.webRequest.onHeadersReceived((details, cb) => {\n"
        "  cb({ responseHeaders: { 'Content-Security-Policy': ['script-src self'] } });\n"
        "});\n",
    )
    payload = audit_electron_app(tmp_path).to_dict()
    ids = {f["rule_id"] for f in payload["findings"]}
    assert "EA-010" not in ids


# ---- preload bridge rule --------------------------------------------------------


def test_contextbridge_variable_channel_flagged(tmp_path: Path) -> None:
    """A caller-chosen IPC channel behind exposeInMainWorld trips EA-031."""
    _write(
        tmp_path,
        "preload.js",
        "const { contextBridge, ipcRenderer } = require('electron');\n"
        "contextBridge.exposeInMainWorld('api', {\n"
        "  send: (channel, payload) => ipcRenderer.send(channel, payload),\n"
        "});\n",
    )
    payload = audit_electron_app(tmp_path).to_dict()
    ids = {f["rule_id"] for f in payload["findings"]}
    assert ids == {"EA-031", "EA-010"}
    finding = next(f for f in payload["findings"] if f["rule_id"] == "EA-031")
    assert finding["severity"] == "medium"
    assert finding["confidence"] == "heuristic"
    assert finding["line"] == 3


# ---- ASAR scans ----------------------------------------------------------------


def test_asar_audit_reads_archive_entries(tmp_path: Path) -> None:
    """The archive lane audits the same patterns without extracting to disk."""
    archive = _build_asar(
        tmp_path,
        {
            "package.json": b'{"name": "packed", "main": "main.js"}',
            "main.js": (
                b"const { BrowserWindow } = require('electron');\n"
                b"const win = new BrowserWindow({\n"
                b"  webPreferences: { nodeIntegration: true, contextIsolation: false },\n"
                b"});\n"
            ),
            "index.html": b"<html><body>no csp here</body></html>\n",
        },
    )
    payload = audit_electron_app(archive).to_dict()
    assert payload["kind"] == "asar"
    ids = {f["rule_id"] for f in payload["findings"]}
    assert {"EA-001", "EA-002", "EA-010"} <= ids
    ea001 = next(f for f in payload["findings"] if f["rule_id"] == "EA-001")
    assert ea001["file"] == "main.js"
    assert ea001["line"] == 3
    assert payload["scanned_files"] == 2
    assert payload["context"]["package"]["name"] == "packed"
    assert payload["evidence"]["method"] == "asar_listing"


# ---- bounds and typed errors -----------------------------------------------------


def test_findings_cap_counts_beyond_and_flags_truncated(tmp_path: Path) -> None:
    """Finding counting continues past the kept cap and truncated is set."""
    for index in range(MAX_FINDINGS + 10):
        _write(tmp_path, f"f{index}.js", "// pad\nnodeIntegration: true\n")
    payload = audit_electron_app(tmp_path).to_dict()
    assert payload["finding_count"] == MAX_FINDINGS + 11  # + EA-010
    assert payload["findings_kept"] == MAX_FINDINGS
    assert payload["truncated"]


def test_per_file_findings_cap(tmp_path: Path) -> None:
    """The per-file cap keeps only MAX_FINDINGS_PER_FILE rows from one file."""
    _write(tmp_path, "many.js", "nodeIntegration: true\n" * 100)
    payload = audit_electron_app(tmp_path).to_dict()
    assert payload["finding_count"] == 101  # 100 matches + EA-010
    assert payload["findings_kept"] == MAX_FINDINGS_PER_FILE + 1
    assert payload["truncated"]


def test_max_files_truncates_with_honest_count(tmp_path: Path) -> None:
    """Scanning stops at max_files while file_count keeps counting."""
    for index in range(5):
        _write(tmp_path, f"f{index}.js", f"// {index}\n")
    payload = audit_electron_app(tmp_path, max_files=2).to_dict()
    assert payload["scanned_files"] == 2
    assert payload["file_count"] == 5
    assert payload["truncated"]


def test_bad_utf8_file_skipped_with_warning(tmp_path: Path) -> None:
    """Non-UTF-8 source degrades to a warning for that file, not a crash."""
    (tmp_path / "binary.js").write_bytes(b"\xff\xfe\x00const x = 1;\n")
    payload = audit_electron_app(tmp_path).to_dict()
    assert payload["scanned_files"] == 0
    assert payload["skipped"]["unreadable"] == 1
    assert any("binary.js" in w for w in payload["warnings"])
    assert payload["findings"] == []  # nothing scanned -> no absence finding


def test_typed_errors_for_bad_inputs(tmp_path: Path) -> None:
    """Missing paths, wrong kinds and bad caps raise typed errors."""
    with pytest.raises(AnalysisError, match="cannot stat"):
        audit_electron_app(tmp_path / "missing")
    plain = tmp_path / "notes.txt"
    plain.write_text("hi", encoding="utf-8")
    with pytest.raises(AnalysisError, match="neither a directory nor an .asar"):
        audit_electron_app(plain)
    with pytest.raises(AnalysisError, match="max_files"):
        audit_electron_app(tmp_path, max_files=0)
    with pytest.raises(AnalysisError, match="max_files"):
        audit_electron_app(tmp_path, max_files=MAX_FILES + 1)


# ---- CLI ------------------------------------------------------------------------


def test_cli_js_audit_table_and_json(tmp_path: Path) -> None:
    """`codevanta js audit` renders findings and --json round-trips."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    (tmp_path / "package.json").write_text('{"name": "vuln"}', encoding="utf-8")
    (tmp_path / "main.js").write_text(
        "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["js", "audit", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "EA-001" in result.output

    result = runner.invoke(cli, ["js", "audit", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "EA-001" in [f["rule_id"] for f in payload["findings"]]


def test_cli_js_audit_error_exit(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["js", "audit", str(tmp_path / "missing")])
    assert result.exit_code == 2
    assert "cannot stat" in result.output

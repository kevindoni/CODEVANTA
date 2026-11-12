"""Setup plan tests: plan-first, idempotent, backup, uninstall."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.setup.apply import apply_plan
from codevanta.setup.clients import (
    ClaudeCodeClient,
    ClineClient,
    CursorClient,
    SetupContext,
    SetupError,
    VsCodeClient,
    detected_clients,
    get_client,
)

runner = CliRunner()


def _context(tmp_path: Path) -> SetupContext:
    return SetupContext(
        home=tmp_path / "home",
        project_dir=tmp_path / "project",
        appdata=tmp_path / "appdata",
    )


def test_cursor_plan_creates_file(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    plan = CursorClient().plan(ctx, "user")
    assert plan.has_changes
    change = plan.changes[0]
    assert change.action == "create"
    assert change.path == ctx.home / ".cursor" / "mcp.json"
    data = json.loads(change.new_content)
    assert data["mcpServers"]["codevanta"]["command"] == "codevanta"
    assert data["mcpServers"]["codevanta"]["args"] == ["mcp", "serve"]


def test_plan_is_idempotent(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    apply_plan(CursorClient().plan(ctx, "user"))
    second = CursorClient().plan(ctx, "user")
    assert second.has_changes is False
    assert second.changes[0].action == "noop"


def test_plan_preserves_other_servers(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    path = ctx.home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}), encoding="utf-8")
    plan = CursorClient().plan(ctx, "user")
    data = json.loads(plan.changes[0].new_content)
    assert "other" in data["mcpServers"]
    assert "codevanta" in data["mcpServers"]


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    path = ctx.home / ".claude.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SetupError):
        ClaudeCodeClient().plan(ctx, "user")


def test_vscode_uses_servers_key(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    plan = VsCodeClient().plan(ctx, "project")
    data = json.loads(plan.changes[0].new_content)
    assert "servers" in data
    assert data["servers"]["codevanta"]["type"] == "stdio"


def test_cline_uses_appdata(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    plan = ClineClient().plan(ctx, "user")
    assert "saoudrizwan.claude-dev" in str(plan.changes[0].path)


def test_unsupported_scope_is_rejected(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    with pytest.raises(SetupError):
        ClineClient().plan(ctx, "project")
    with pytest.raises(SetupError):
        VsCodeClient().plan(ctx, "user")


def test_apply_writes_backup(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    path = ctx.home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"mcpServers": {}}', encoding="utf-8")
    apply_plan(CursorClient().plan(ctx, "user"))
    backup = path.with_name("mcp.json.codevanta.bak")
    assert backup.exists()
    assert "codevanta" in path.read_text(encoding="utf-8")


def test_uninstall_removes_only_codevanta(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    path = ctx.home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "other": {"command": "other"},
                    "codevanta": {"command": "codevanta", "args": ["mcp", "serve"]},
                }
            }
        ),
        encoding="utf-8",
    )
    plan = CursorClient().removal_plan(ctx, "user")
    data = json.loads(plan.changes[0].new_content)
    assert "codevanta" not in data["mcpServers"]
    assert "other" in data["mcpServers"]


def test_uninstall_missing_file_is_noop(tmp_path: Path) -> None:
    plan = CursorClient().removal_plan(_context(tmp_path), "user")
    assert plan.has_changes is False


def test_registry_aliases() -> None:
    assert get_client("claude-code").name == "claude"
    assert get_client("vs-code").name == "vscode"
    with pytest.raises(SetupError):
        get_client("unknown")


def test_detection(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    (ctx.home / ".cursor").mkdir(parents=True)
    (ctx.home / ".cursor" / "mcp.json").write_text("{}", encoding="utf-8")
    names = {adapter.name for adapter in detected_clients(ctx)}
    assert names == {"cursor"}


def test_cli_setup_dry_run_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("CODEVANTA_HOME", str(home))
    result = runner.invoke(app, ["setup", "--client", "cursor", "--dry-run"])
    assert result.exit_code == 0, result.stdout
    assert "dry run" in result.stdout
    assert not (home / ".cursor" / "mcp.json").exists()


def test_cli_setup_apply_then_uninstall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("CODEVANTA_HOME", str(home))
    applied = runner.invoke(app, ["setup", "--client", "cursor", "--yes", "--verify"])
    assert applied.exit_code == 0, applied.stdout
    path = home / ".cursor" / "mcp.json"
    assert path.exists()
    removed = runner.invoke(app, ["uninstall", "--client", "cursor", "--yes"])
    assert removed.exit_code == 0, removed.stdout
    assert "codevanta" not in path.read_text(encoding="utf-8")

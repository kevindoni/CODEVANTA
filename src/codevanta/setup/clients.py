"""Client adapters that know where each coding agent stores MCP settings."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .plan import SetupPlan, make_change


class SetupError(Exception):
    """Raised when a setup request cannot be planned safely."""


SERVER_KEY = "codevanta"
SERVER_COMMAND = "codevanta"
SERVER_ARGS = ("mcp", "serve")


@dataclass(frozen=True)
class SetupContext:
    """Filesystem roots used to locate client configuration files."""

    home: Path
    project_dir: Path
    appdata: Path

    @classmethod
    def from_environment(cls, project_dir: str | Path | None = None) -> SetupContext:
        home_env = os.environ.get("CODEVANTA_HOME")
        home = Path(home_env).expanduser() if home_env else Path.home()
        appdata_env = os.environ.get("APPDATA")
        appdata = Path(appdata_env) if appdata_env else home / "AppData" / "Roaming"
        project = Path(project_dir).expanduser() if project_dir else Path.cwd()
        return cls(home=home, project_dir=project, appdata=appdata)


def _dump(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _parse(previous: str, path: Path) -> dict[str, Any]:
    if not previous.strip():
        return {}
    try:
        data = json.loads(previous)
    except json.JSONDecodeError as exc:
        raise SetupError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise SetupError(f"{path}: expected a JSON object at the top level")
    return data


class ClientAdapter(ABC):
    """Base class for a coding-agent MCP configuration adapter."""

    name: str
    display_name: str
    supports_user_scope: bool = True
    supports_project_scope: bool = True

    @property
    @abstractmethod
    def container_key(self) -> str:
        """Top-level JSON object that holds MCP servers."""

    @abstractmethod
    def config_path(self, ctx: SetupContext, scope: str) -> Path:
        """Return the configuration file for ``scope``."""

    @abstractmethod
    def build_entry(self) -> dict[str, Any]:
        """Return the MCP server entry for this client."""

    def plan(self, ctx: SetupContext, scope: str) -> SetupPlan:
        return self._plan(ctx, scope, remove=False)

    def removal_plan(self, ctx: SetupContext, scope: str) -> SetupPlan:
        return self._plan(ctx, scope, remove=True)

    def _plan(self, ctx: SetupContext, scope: str, remove: bool) -> SetupPlan:
        if scope not in ("user", "project"):
            raise SetupError(f"unknown scope {scope!r}; use 'user' or 'project'")
        if scope == "user" and not self.supports_user_scope:
            raise SetupError(f"{self.display_name} does not support user scope")
        if scope == "project" and not self.supports_project_scope:
            raise SetupError(f"{self.display_name} does not support project scope")
        path = self.config_path(ctx, scope)
        if remove and not path.exists():
            return SetupPlan(
                client=self.name,
                scope=scope,
                changes=(make_change(path, "", ""),),
                notes=("configuration file not found",),
            )
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
        data = _parse(previous, path)
        servers = data.get(self.container_key)
        if servers is None:
            servers = {}
            data[self.container_key] = servers
        if not isinstance(servers, dict):
            raise SetupError(f"{path}: '{self.container_key}' must be a JSON object")
        notes: list[str] = []
        if remove:
            if SERVER_KEY in servers:
                del servers[SERVER_KEY]
                notes.append("removed CODEVANTA entry")
            else:
                notes.append("CODEVANTA is not registered here")
        else:
            desired = self.build_entry()
            if servers.get(SERVER_KEY) == desired:
                notes.append("already configured")
            else:
                servers[SERVER_KEY] = desired
                notes.append("registered CODEVANTA")
        change = make_change(path, previous, _dump(data))
        return SetupPlan(client=self.name, scope=scope, changes=(change,), notes=tuple(notes))

    def detected(self, ctx: SetupContext) -> bool:
        scopes = []
        if self.supports_user_scope:
            scopes.append("user")
        if self.supports_project_scope:
            scopes.append("project")
        for scope in scopes:
            try:
                if self.config_path(ctx, scope).exists():
                    return True
            except SetupError:
                continue
        return False


class ClaudeCodeClient(ClientAdapter):
    """Claude Code: ~/.claude.json or project .mcp.json."""

    name = "claude"
    display_name = "Claude Code"
    container_key = "mcpServers"

    def config_path(self, ctx: SetupContext, scope: str) -> Path:
        if scope == "user":
            return ctx.home / ".claude.json"
        return ctx.project_dir / ".mcp.json"

    def build_entry(self) -> dict[str, Any]:
        return {"command": SERVER_COMMAND, "args": list(SERVER_ARGS)}


class CursorClient(ClientAdapter):
    """Cursor: ~/.cursor/mcp.json or project .cursor/mcp.json."""

    name = "cursor"
    display_name = "Cursor"
    container_key = "mcpServers"

    def config_path(self, ctx: SetupContext, scope: str) -> Path:
        if scope == "user":
            return ctx.home / ".cursor" / "mcp.json"
        return ctx.project_dir / ".cursor" / "mcp.json"

    def build_entry(self) -> dict[str, Any]:
        return {"command": SERVER_COMMAND, "args": list(SERVER_ARGS)}


class ClineClient(ClientAdapter):
    """Cline (VS Code extension): global storage settings, user scope only."""

    name = "cline"
    display_name = "Cline (VS Code)"
    supports_project_scope = False
    container_key = "mcpServers"

    def config_path(self, ctx: SetupContext, scope: str) -> Path:
        if scope != "user":
            raise SetupError("Cline only supports user scope")
        return (
            ctx.appdata
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json"
        )

    def build_entry(self) -> dict[str, Any]:
        return {
            "command": SERVER_COMMAND,
            "args": list(SERVER_ARGS),
            "disabled": False,
            "autoApprove": [],
        }


class VsCodeClient(ClientAdapter):
    """VS Code (Copilot): project-scope .vscode/mcp.json only."""

    name = "vscode"
    display_name = "VS Code (Copilot)"
    supports_user_scope = False
    container_key = "servers"

    def config_path(self, ctx: SetupContext, scope: str) -> Path:
        if scope != "project":
            raise SetupError("VS Code support writes project-scope .vscode/mcp.json only")
        return ctx.project_dir / ".vscode" / "mcp.json"

    def build_entry(self) -> dict[str, Any]:
        return {"type": "stdio", "command": SERVER_COMMAND, "args": list(SERVER_ARGS)}


CLIENTS: dict[str, type[ClientAdapter]] = {
    "claude": ClaudeCodeClient,
    "cursor": CursorClient,
    "cline": ClineClient,
    "vscode": VsCodeClient,
}

ALIASES: dict[str, str] = {
    "claude-code": "claude",
    "claude_code": "claude",
    "vs-code": "vscode",
    "code": "vscode",
}


def get_client(name: str) -> ClientAdapter:
    """Return a client adapter by name or alias."""
    key = ALIASES.get(name.lower(), name.lower())
    try:
        return CLIENTS[key]()
    except KeyError as exc:
        options = ", ".join(sorted(CLIENTS))
        raise SetupError(f"unknown client {name!r}; choose from {options}") from exc


def detected_clients(ctx: SetupContext) -> list[ClientAdapter]:
    """Return adapters whose configuration files already exist."""
    return [cls() for cls in CLIENTS.values() if cls().detected(ctx)]


def describe_clients(ctx: SetupContext) -> list[dict[str, Any]]:
    """Return a status row for every supported client and scope."""
    rows: list[dict[str, Any]] = []
    for cls in CLIENTS.values():
        adapter = cls()
        for scope in ("user", "project"):
            if scope == "user" and not adapter.supports_user_scope:
                continue
            if scope == "project" and not adapter.supports_project_scope:
                continue
            path = adapter.config_path(ctx, scope)
            status = "missing"
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    status = "invalid JSON"
                else:
                    servers = data.get(adapter.container_key) if isinstance(data, dict) else None
                    if isinstance(servers, dict) and servers.get(SERVER_KEY) == adapter.build_entry():
                        status = "registered"
                    elif isinstance(servers, dict) and SERVER_KEY in servers:
                        status = "different entry"
                    else:
                        status = "not registered"
            rows.append(
                {
                    "client": adapter.name,
                    "display": adapter.display_name,
                    "scope": scope,
                    "path": str(path),
                    "status": status,
                }
            )
    return rows



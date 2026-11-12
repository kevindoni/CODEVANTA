"""Post-setup verification: configuration entry and tool layer."""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

from .clients import SERVER_KEY, ClientAdapter, SetupContext


def verify_entry(adapter: ClientAdapter, ctx: SetupContext, scope: str) -> dict[str, Any]:
    """Confirm that the client configuration contains the expected entry."""
    path = adapter.config_path(ctx, scope)
    if not path.exists():
        return {"ok": False, "path": str(path), "detail": "configuration file not found"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"ok": False, "path": str(path), "detail": f"invalid JSON: {exc.msg}"}
    servers = data.get(adapter.container_key) or {}
    entry = servers.get(SERVER_KEY) if isinstance(servers, dict) else None
    ok = entry == adapter.build_entry()
    detail = "entry present" if ok else "entry missing or different"
    return {"ok": ok, "path": str(path), "detail": detail}


def verify_tools() -> dict[str, Any]:
    """Run one tool call on a synthetic ELF to prove the tool layer works."""
    from mcp_server import tools

    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "sample_elf64.bin"
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        header = struct.pack(
            "<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0
        )
        sample.write_bytes(ident + header)
        info = tools.binary_info(str(sample))
    ok = info.get("format") == "ELF" and info.get("architecture") == "x86_64"
    return {"ok": ok, "detail": "tool layer responded", "format": info.get("format")}

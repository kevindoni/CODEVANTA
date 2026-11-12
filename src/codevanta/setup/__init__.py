"""CODEVANTA setup helpers for coding-agent MCP configuration."""

from .apply import apply_plan
from .clients import (
    CLIENTS,
    ClientAdapter,
    SetupContext,
    SetupError,
    detected_clients,
    get_client,
)
from .plan import FileChange, SetupPlan, make_change
from .verify import verify_entry, verify_tools

__all__ = [
    "CLIENTS",
    "ClientAdapter",
    "FileChange",
    "SetupContext",
    "SetupError",
    "SetupPlan",
    "apply_plan",
    "detected_clients",
    "get_client",
    "make_change",
    "verify_entry",
    "verify_tools",
]

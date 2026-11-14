"""MCP tools exposing the IL2CPP and GPU inspectors (no MCP imports)."""

from __future__ import annotations

from typing import Any

from codevanta.analysis.gpu_meta import inspect_gpu
from codevanta.analysis.il2cpp_meta import parse_il2cpp_meta


def codevanta_il2cpp(path: str) -> dict[str, Any]:
    """Parse IL2CPP global-metadata header structure (structure only)."""
    return parse_il2cpp_meta(path).to_dict()


def codevanta_gpu(path: str) -> dict[str, Any]:
    """Inspect a CUDA fatbin, CUBIN, or Clang offload bundle."""
    return inspect_gpu(path).to_dict()

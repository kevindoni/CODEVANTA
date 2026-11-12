"""Registry for IR adapters. Concrete adapters arrive in phase 4."""

from __future__ import annotations

from ..base import IRAdapter

_ADAPTERS: dict[str, type[IRAdapter]] = {}


def register_adapter(adapter_cls: type[IRAdapter]) -> type[IRAdapter]:
    """Register an adapter class under its ``name`` attribute."""
    if not adapter_cls.name or adapter_cls.name == "base":
        raise ValueError("adapter must define a unique non-'base' name")
    _ADAPTERS[adapter_cls.name] = adapter_cls
    return adapter_cls


def available_adapters() -> list[str]:
    """Return the names of all registered adapters."""
    return sorted(_ADAPTERS)


def get_adapter(name: str) -> IRAdapter:
    """Instantiate a registered adapter by name."""
    try:
        return _ADAPTERS[name]()
    except KeyError as exc:
        raise KeyError(f"Unknown IR adapter: {name!r}") from exc


__all__ = ["register_adapter", "available_adapters", "get_adapter"]

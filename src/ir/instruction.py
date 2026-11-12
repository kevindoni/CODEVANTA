"""Normalized instruction model shared by all IR adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IRInstruction:
    """A single decoded instruction in a backend-neutral form.

    Phase 1 fills the structural fields only (address, size, mnemonic,
    operands, raw bytes). ``ir_ops`` stays empty until an adapter (VEX,
    P-Code, custom) lifts the instruction in a later phase.
    """

    address: int
    size: int
    mnemonic: str
    operands: str
    raw_bytes: bytes
    section: str | None = None
    ir_ops: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def text(self) -> str:
        """Return ``"mnemonic operands"`` (or just the mnemonic)."""
        return f"{self.mnemonic} {self.operands}".strip()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "address": f"0x{self.address:x}",
            "size": self.size,
            "bytes": self.raw_bytes.hex(),
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "text": self.text,
        }
        if self.section:
            data["section"] = self.section
        return data

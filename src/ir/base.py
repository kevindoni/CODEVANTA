"""IR adapter contract for future lifting backends (VEX, P-Code, ...)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from typing import Any

from .instruction import IRInstruction


class IRAdapter(ABC):
    """Base class for instruction lifting backends.

    Adapters convert structural instructions into an intermediate
    representation. Phase 1 ships no concrete adapter; the contract keeps the
    core engine independent from any specific IR.
    """

    name: str = "base"

    @abstractmethod
    def lift(self, instruction: IRInstruction) -> Sequence[dict[str, Any]]:
        """Lift one instruction into IR operations."""

    def lift_many(self, instructions: Iterable[IRInstruction]) -> list[dict[str, Any]]:
        """Lift several instructions, preserving their order."""
        lifted: list[dict[str, Any]] = []
        for instruction in instructions:
            lifted.extend(self.lift(instruction))
        return lifted

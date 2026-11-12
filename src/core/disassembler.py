"""Capstone-backed disassembly for supported architectures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import capstone

from evidence.confidence import Confidence
from evidence.models import Evidence
from ir.instruction import IRInstruction


class DisassemblyError(Exception):
    """Raised when disassembly cannot be performed."""


@dataclass(frozen=True)
class DisassemblyResult:
    """Outcome of a single disassembly request."""

    instructions: list[IRInstruction]
    base_address: int
    consumed_bytes: int
    evidence: Evidence
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_address": f"0x{self.base_address:x}",
            "consumed_bytes": self.consumed_bytes,
            "truncated": self.truncated,
            "instruction_count": len(self.instructions),
            "instructions": [i.to_dict() for i in self.instructions],
            "evidence": self.evidence.to_dict(),
        }


_ARCH_MAP: dict[tuple[str, int], tuple[int, int]] = {
    ("x86", 32): (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    ("x86", 64): (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    ("x86_64", 64): (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    ("arm", 32): (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    ("aarch64", 64): (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    ("arm64", 64): (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    ("mips", 32): (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
    ("mips", 64): (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64),
}


class Disassembler:
    """Disassembles machine code with Capstone."""

    MAX_BYTES = 16 * 1024 * 1024
    MAX_INSTRUCTIONS = 1_000_000

    def __init__(self, architecture: str, bitness: int, endianness: str = "little") -> None:
        self.architecture = architecture
        self.bitness = bitness
        self.endianness = endianness
        arch_mode = _ARCH_MAP.get((architecture.lower(), bitness))
        if arch_mode is None:
            raise DisassemblyError(f"Unsupported architecture: {architecture} ({bitness}-bit)")
        cs_arch, cs_mode = arch_mode
        if endianness.lower() == "big":
            if cs_arch in (capstone.CS_ARCH_ARM, capstone.CS_ARCH_MIPS):
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            elif cs_arch == capstone.CS_ARCH_X86:
                raise DisassemblyError("x86 is little-endian only")
            elif cs_arch == capstone.CS_ARCH_ARM64:
                raise DisassemblyError("big-endian AArch64 is not supported")
        self._cs = capstone.Cs(cs_arch, cs_mode)
        self._cs.detail = False

    def disassemble(
        self,
        data: bytes,
        base_address: int,
        max_instructions: int = 0,
        max_bytes: int = 0,
    ) -> DisassemblyResult:
        """Decode ``data`` starting at ``base_address``."""
        if not data:
            raise DisassemblyError("No bytes supplied for disassembly")
        if base_address < 0:
            raise DisassemblyError("base_address must be non-negative")
        byte_limit = min(len(data), max_bytes if max_bytes > 0 else self.MAX_BYTES)
        instruction_limit = max_instructions if max_instructions > 0 else self.MAX_INSTRUCTIONS
        window = data[:byte_limit]
        instructions: list[IRInstruction] = []
        consumed = 0
        truncated = byte_limit < len(data)
        for insn in self._cs.disasm(window, base_address):
            instructions.append(
                IRInstruction(
                    address=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    raw_bytes=bytes(insn.bytes),
                )
            )
            consumed += insn.size
            if len(instructions) >= instruction_limit:
                truncated = truncated or consumed < len(window)
                break
        evidence = Evidence(
            source="capstone",
            method="linear_disassembly",
            confidence=Confidence.CERTAIN,
            address=base_address,
            detail=f"{len(instructions)} instruction(s) decoded",
        )
        return DisassemblyResult(
            instructions=instructions,
            base_address=base_address,
            consumed_bytes=consumed,
            evidence=evidence,
            truncated=truncated,
        )

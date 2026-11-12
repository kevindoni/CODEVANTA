"""Function candidate discovery with explicit provenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from evidence.confidence import Confidence
from evidence.models import Evidence

from .loader import BinaryInfo


@dataclass(frozen=True)
class FunctionCandidate:
    """A function candidate and the evidence that identified it."""

    address: int
    name: str | None
    size: int | None
    source: str
    confidence: Confidence
    evidence: Evidence
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "address": f"0x{self.address:x}",
            "source": self.source,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict(),
        }
        if self.name:
            data["name"] = self.name
        if self.size is not None:
            data["size"] = self.size
        if self.aliases:
            data["aliases"] = list(self.aliases)
        return data


@dataclass
class _Draft:
    address: int
    name: str | None
    size: int | None
    source: str
    confidence: Confidence
    evidence: Evidence
    aliases: list[str] = field(default_factory=list)


def discover_functions(info: BinaryInfo) -> list[FunctionCandidate]:
    """Discover function candidates from structural evidence only.

    Phase 1 reports exported functions, function symbols, and the entry point.
    Speculative heuristics are intentionally excluded; every candidate states
    where it came from and how much confidence it deserves.
    """
    drafts: dict[int, _Draft] = {}

    def add(
        address: int | None,
        name: str | None,
        size: int | None,
        source: str,
        confidence: Confidence,
        method: str,
        detail: str,
    ) -> None:
        if not address or address <= 0:
            return
        clean_name = name or None
        evidence = Evidence(
            source=source,
            method=method,
            confidence=confidence,
            address=address,
            detail=detail,
        )
        existing = drafts.get(address)
        if existing is None:
            drafts[address] = _Draft(
                address=address,
                name=clean_name,
                size=size,
                source=source,
                confidence=confidence,
                evidence=evidence,
            )
            return
        if confidence.score > existing.confidence.score:
            if existing.name and existing.name != clean_name:
                existing.aliases.append(existing.name)
            existing.name = clean_name
            existing.size = size if size is not None else existing.size
            existing.source = source
            existing.confidence = confidence
            existing.evidence = evidence
        elif clean_name and clean_name != existing.name and clean_name not in existing.aliases:
            existing.aliases.append(clean_name)

    for export in info.exports:
        add(
            export.address,
            export.name,
            None,
            "pe.export_table" if info.format == "PE" else "elf.dynsym",
            Confidence.HIGH,
            "exported_function",
            "exported function entry",
        )

    for symbol in info.symbols:
        if not symbol.is_function:
            continue
        add(
            symbol.address,
            symbol.name,
            symbol.size or None,
            "elf.symtab" if info.format == "ELF" else "pe.coff_symbols",
            Confidence.HIGH,
            "function_symbol",
            "function symbol from the symbol table",
        )

    if info.entry_point:
        add(
            info.entry_point,
            None,
            None,
            "binary.entry_point",
            Confidence.MEDIUM,
            "entry_point",
            "program entry point; a code candidate, not a proven function boundary",
        )

    candidates = [
        FunctionCandidate(
            address=draft.address,
            name=draft.name,
            size=draft.size,
            source=draft.source,
            confidence=draft.confidence,
            evidence=draft.evidence,
            aliases=tuple(dict.fromkeys(draft.aliases)),
        )
        for draft in drafts.values()
    ]
    candidates.sort(key=lambda c: c.address)
    return candidates

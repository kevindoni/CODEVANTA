"""ASCII and UTF-16LE string extraction with location mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

from .loader import BinaryInfo


@dataclass(frozen=True)
class StringResult:
    """A string found in the file with its offset and mapped address."""

    offset: int
    address: int | None
    text: str
    encoding: str
    length: int
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "offset": f"0x{self.offset:x}",
            "text": self.text,
            "encoding": self.encoding,
            "length": self.length,
        }
        if self.address is not None:
            data["address"] = f"0x{self.address:x}"
        return data


class StringExtractor:
    """Extracts printable ASCII and UTF-16LE strings from a file."""

    def __init__(self, min_length: int = 4) -> None:
        if min_length < 1:
            raise ValueError("min_length must be >= 1")
        self.min_length = min_length

    def extract(
        self,
        path: str | Path,
        info: BinaryInfo | None = None,
        limit: int = 0,
    ) -> list[StringResult]:
        """Extract strings from ``path``; ``limit`` caps the result count."""
        data = Path(path).read_bytes()
        results: list[StringResult] = []
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % self.min_length)
        for match in ascii_pattern.finditer(data):
            text = match.group().decode("ascii", errors="replace")
            results.append(self._result(match.start(), text, "ascii", info))
        utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % self.min_length)
        for match in utf16_pattern.finditer(data):
            text = match.group().decode("utf-16-le", errors="replace")
            results.append(self._result(match.start(), text, "utf-16le", info))
        results.sort(key=lambda r: (r.offset, r.encoding))
        if limit and len(results) > limit:
            return results[:limit]
        return results

    @staticmethod
    def _result(offset: int, text: str, encoding: str, info: BinaryInfo | None) -> StringResult:
        address = info.offset_to_va(offset) if info is not None else None
        evidence = Evidence(
            source="string_scanner",
            method=f"{encoding}_scan",
            confidence=Confidence.HIGH if address is not None else Confidence.MEDIUM,
            address=address,
            detail=f"{encoding} string, {len(text)} chars",
        )
        return StringResult(
            offset=offset,
            address=address,
            text=text,
            encoding=encoding,
            length=len(text),
            evidence=evidence,
        )

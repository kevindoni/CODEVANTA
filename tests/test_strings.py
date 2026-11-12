"""String extraction tests."""

from __future__ import annotations

from pathlib import Path

from codevanta.core.strings import StringExtractor


def test_extracts_ascii_and_utf16(tmp_path: Path) -> None:
    data = b"\x00\x00Hello World\x00\x00" + "Wide".encode("utf-16-le") + b"\x00\x00"
    sample = tmp_path / "strings.bin"
    sample.write_bytes(data)
    results = StringExtractor(min_length=4).extract(sample)
    found = {(r.text, r.encoding) for r in results}
    assert ("Hello World", "ascii") in found
    assert ("Wide", "utf-16le") in found


def test_respects_min_length(tmp_path: Path) -> None:
    sample = tmp_path / "short.bin"
    sample.write_bytes(b"abc\x00abcdef")
    results = StringExtractor(min_length=4).extract(sample)
    assert [r.text for r in results] == ["abcdef"]


def test_limit_caps_results(tmp_path: Path) -> None:
    sample = tmp_path / "many.bin"
    sample.write_bytes(b"alpha\x00bravo\x00charlie\x00")
    results = StringExtractor(min_length=4).extract(sample, limit=2)
    assert len(results) == 2


def test_offsets_are_reported(tmp_path: Path) -> None:
    sample = tmp_path / "offset.bin"
    sample.write_bytes(b"\x00\x00\x00\x00marker")
    results = StringExtractor(min_length=4).extract(sample)
    assert results[0].offset == 4
    assert results[0].evidence.source == "string_scanner"

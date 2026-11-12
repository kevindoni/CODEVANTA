"""String extraction tests."""

from __future__ import annotations

from pathlib import Path

from codevanta.core.loader import BinaryInfo
from codevanta.core.strings import StringExtractor


def _info(endianness: str) -> BinaryInfo:
    """Minimal metadata; only endianness matters for byte-order selection."""
    return BinaryInfo(
        path=Path("dummy"),
        format="ELF",
        architecture="mips",
        bitness=64,
        endianness=endianness,
        entry_point=None,
        image_base=0,
        sha256="0" * 64,
        file_size=0,
    )


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


def test_big_endian_binary_yields_utf16be(tmp_path: Path) -> None:
    data = b"\x00\x00" + "WideBE".encode("utf-16-be") + b"\x00\x00"
    sample = tmp_path / "be.bin"
    sample.write_bytes(data)
    results = StringExtractor(min_length=4).extract(sample, info=_info("big"))
    found = {(r.text, r.encoding) for r in results}
    assert ("WideBE", "utf-16be") in found
    assert all(r.encoding != "utf-16le" for r in results)


def test_little_endian_binary_keeps_utf16le(tmp_path: Path) -> None:
    data = b"\x00\x00" + "WideLE".encode("utf-16-le") + b"\x00\x00"
    sample = tmp_path / "le.bin"
    sample.write_bytes(data)
    results = StringExtractor(min_length=4).extract(sample, info=_info("little"))
    found = {(r.text, r.encoding) for r in results}
    assert ("WideLE", "utf-16le") in found
    assert all(r.encoding != "utf-16be" for r in results)


def test_no_info_never_guesses_big_endian(tmp_path: Path) -> None:
    data = b"\x00\x00" + "WideBE".encode("utf-16-be") + b"\x00\x00"
    sample = tmp_path / "raw.bin"
    sample.write_bytes(data)
    results = StringExtractor(min_length=4).extract(sample)
    assert all(r.encoding != "utf-16be" for r in results)


def test_utf16be_evidence_uses_be_method(tmp_path: Path) -> None:
    data = "EvidenceBE".encode("utf-16-be")
    sample = tmp_path / "evidence.bin"
    sample.write_bytes(data)
    results = StringExtractor(min_length=4).extract(sample, info=_info("big"))
    match = next(r for r in results if r.encoding == "utf-16be")
    assert match.evidence.method == "utf-16be_scan"
    assert match.evidence.source == "string_scanner"

"""Entropy triage tests (per-section measurement and packed hints)."""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.cli.main import app
from codevanta.core.entropy import analyze_entropy, shannon_entropy
from codevanta.core.loader import BinaryLoader
from codevanta.core.report import AnalysisError

runner = CliRunner()

TEXT_ADDRESS = 0x401000
#: Deterministic high-entropy payload (a seeded PRNG is enough for entropy).
RANDOM_BYTES = random.Random(1234).randbytes(2048)
REPETITIVE_BYTES = b"A" * 2048
TINY_RANDOM = random.Random(99).randbytes(32)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _write_elf64_sections(path: Path, sections: list[tuple[str, int, bytes | None]]) -> Path:
    """Write an ELF64 with the given (name, sh_flags, data-or-None) sections.

    ``None`` data means SHT_NOBITS with offset 0 (no file bytes). Local helper
    so the entropy tests control section payloads precisely.
    """
    shstr = bytearray(b"\x00")
    names: dict[str, int] = {}
    for name, _, _ in sections:
        names[name] = len(shstr)
        shstr += name.encode() + b"\x00"
    names[".shstrtab"] = len(shstr)
    shstr += b".shstrtab\x00"
    shstr = bytes(shstr)

    data_offset = 0x40
    layout: list[tuple[str, int, int, bytes | None]] = []  # name, offset, size, data
    cursor = data_offset
    for name, _flags, data in sections:
        if data is None:
            layout.append((name, 0, 256, None))  # NOBITS: no file bytes, offset 0
        else:
            layout.append((name, cursor, len(data), data))
            cursor = _align(cursor + len(data), 8)
    shstrtab_offset = cursor
    shoff = _align(shstrtab_offset + len(shstr), 8)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        TEXT_ADDRESS,  # e_entry
        0,
        shoff,
        0,
        64,
        56,
        0,
        64,
        len(sections) + 2,  # null + sections + shstrtab
        len(sections) + 1,
    )
    blob = bytearray(shoff + (len(sections) + 2) * 64)
    blob[0:64] = header
    for _name, offset, _, data in layout:
        if data is not None:
            blob[offset : offset + len(data)] = data
    blob[shstrtab_offset : shstrtab_offset + len(shstr)] = shstr

    def section_header(name_index: int, sh_type: int, flags: int, addr: int, offset: int, size: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_index,
            sh_type,
            flags,
            addr,
            offset,
            size,
            0,
            0,
            1,
            0,
        )

    blob[shoff : shoff + 64] = bytes(64)  # null section
    position = shoff + 64
    for index, (name, flags, data) in enumerate(sections):
        _, offset, size, _ = layout[index]
        sh_type = 8 if data is None else 1  # SHT_NOBITS / SHT_PROGBITS
        # NOBITS lives far from file-backed sections so nothing maps into it.
        address = TEXT_ADDRESS + 0x10000 if data is None else offset
        blob[position : position + 64] = section_header(
            names[name], sh_type, flags, address, offset, size
        )
        position += 64
    blob[position : position + 64] = section_header(
        names[".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstr)
    )
    path.write_bytes(bytes(blob))
    return path


def _high_entropy_sample(tmp_path: Path) -> Path:
    return _write_elf64_sections(
        tmp_path / "packed.bin",
        [
            (".text", 0x6, RANDOM_BYTES),
            (".data", 0x3, REPETITIVE_BYTES),
            (".bss", 0x3, None),
        ],
    )


def test_random_section_flags_packed_hint(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    info = BinaryLoader().load(sample)
    report = analyze_entropy(sample, info)
    by_name = {section.name: section for section in report.sections}
    assert by_name[".text"].entropy is not None and by_name[".text"].entropy >= 7.2
    assert by_name[".text"].packed_hint is True
    assert by_name[".text"].evidence.source == "entropy.section"
    assert by_name[".text"].evidence.confidence.value == "certain"
    assert [section.name for section in report.packed_candidates] == [".text"]


def test_repetitive_section_stays_low_entropy(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    info = BinaryLoader().load(sample)
    report = analyze_entropy(sample, info)
    by_name = {section.name: section for section in report.sections}
    assert by_name[".data"].entropy is not None and by_name[".data"].entropy < 0.1
    assert by_name[".data"].packed_hint is False


def test_non_file_backed_section_has_no_entropy(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    info = BinaryLoader().load(sample)
    report = analyze_entropy(sample, info)
    by_name = {section.name: section for section in report.sections}
    assert by_name[".bss"].entropy is None
    assert by_name[".bss"].packed_hint is False
    assert any(".bss" in warning and "not file-backed" in warning for warning in report.warnings)


def test_small_sample_suppresses_packing_judgment(tmp_path: Path) -> None:
    sample = _write_elf64_sections(tmp_path / "tiny.bin", [(".text", 0x6, TINY_RANDOM)])
    info = BinaryLoader().load(sample)
    report = analyze_entropy(sample, info)
    section = report.sections[0]
    # 32 random bytes top out near log2(32) = 5 bits/byte — measurable, but
    # far too small a sample for any packing judgment.
    assert section.entropy is not None and section.entropy > 4.0
    assert section.packed_hint is False  # suppressed: sample below the floor
    assert "sample too small" in section.evidence.detail


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    wide = bytes(range(256)) * 4
    assert abs(shannon_entropy(wide) - 8.0) < 1e-9


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"threshold": 0.0}, "threshold"),
        ({"threshold": 8.5}, "threshold"),
        ({"max_sample_bytes": 0}, "max_sample_bytes"),
        ({"min_sample_bytes": 0}, "min_sample_bytes"),
    ],
)
def test_invalid_limits_raise(tmp_path: Path, kwargs: dict, message: str) -> None:
    sample = _high_entropy_sample(tmp_path)
    info = BinaryLoader().load(sample)
    with pytest.raises(AnalysisError, match=message):
        analyze_entropy(sample, info, **kwargs)


def test_cli_entropy_table(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    result = runner.invoke(app, ["entropy", str(sample)])
    assert result.exit_code == 0, result.stdout
    assert "Section entropy" in result.stdout
    assert ".text" in result.stdout
    assert "yes" in result.stdout  # packed hint for the random section


def test_cli_entropy_json(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    result = runner.invoke(app, ["entropy", str(sample), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    # .text/.data/.bss plus .shstrtab and the null section from the ELF layout.
    assert payload["section_count"] == 5
    assert payload["packed_candidates"] == [".text"]
    assert all("evidence" in section for section in payload["sections"])


def test_cli_entropy_invalid_threshold_exits_nonzero(tmp_path: Path) -> None:
    sample = _high_entropy_sample(tmp_path)
    result = runner.invoke(app, ["entropy", str(sample), "--threshold", "9"])
    assert result.exit_code != 0

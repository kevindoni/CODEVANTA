"""Tests for the triage hashing engine (imphash + ssdeep-style fuzzy hashing)."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

import pytest

from codevanta.analysis.triage_hash import (
    MAX_BLOCK_SIZE,
    MAX_IMPORTS,
    MIN_BLOCK_SIZE,
    NUM_BLOCK_SIZES,
    SPAMSUM_LENGTH,
    _import_hash_from_info,
    block_size_for_length,
    fuzzy_compare,
    fuzzy_hash_bytes,
    fuzzy_hash_file,
    import_hash,
    triage_hashes,
)
from codevanta.core.loader import BinaryInfo, ImportInfo
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence

SIGNATURE_SHAPE_RE = re.compile(r"^\d+:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{1,64}$")

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def seeded_bytes(label: str, length: int) -> bytes:
    """Deterministic seeded bytes (hashlib-derived, never the random module)."""
    out = bytearray()
    while len(out) < length:
        out.extend(hashlib.sha256(f"{label}:{len(out)}".encode()).digest())
    return bytes(out[:length])


def varied_text(label: str) -> str:
    """A deterministic base64-alphabet string with no character runs."""
    return "".join(_B64[byte % 64] for byte in hashlib.sha256(label.encode()).digest())


# ---- fuzzy hashing ------------------------------------------------------------


@pytest.fixture(scope="module")
def one_mib() -> bytes:
    return seeded_bytes("triage-one", 1024 * 1024)


@pytest.fixture(scope="module")
def one_mib_signature(one_mib: bytes) -> str:
    return fuzzy_hash_bytes(one_mib)


@pytest.fixture(scope="module")
def four_mib_signature() -> str:
    return fuzzy_hash_bytes(seeded_bytes("triage-four", 4 * 1024 * 1024))


def test_fuzzy_hash_bytes_is_deterministic(one_mib: bytes) -> None:
    """Identical bytes produce the identical signature, in ssdeep shape."""
    signature = fuzzy_hash_bytes(one_mib)
    assert signature == fuzzy_hash_bytes(one_mib)
    assert SIGNATURE_SHAPE_RE.match(signature)


def test_signature_shape_is_blocksize_hash_hash(one_mib_signature: str) -> None:
    block_size, part1, part2 = one_mib_signature.split(":")
    assert int(block_size) > 0
    assert 1 <= len(part1) <= SPAMSUM_LENGTH
    assert 1 <= len(part2) <= SPAMSUM_LENGTH // 2
    assert set(part1) <= set(_B64)
    assert set(part2) <= set(_B64)


def test_tiny_input_still_produces_a_signature() -> None:
    """Files smaller than one block hash per ssdeep behavior (tail chars)."""
    signature = fuzzy_hash_bytes(seeded_bytes("tiny", 64))
    assert SIGNATURE_SHAPE_RE.match(signature)
    assert signature.startswith("32768:")


def test_fuzzy_compare_identical_signatures_score_100(one_mib_signature: str) -> None:
    comparison = fuzzy_compare(one_mib_signature, one_mib_signature)
    assert comparison.score == 100
    assert comparison.same_file is True
    assert comparison.evidence.confidence is Confidence.MEDIUM


def test_small_edit_scores_high(one_mib: bytes, one_mib_signature: str) -> None:
    """A 1 KiB edit inside 1 MiB resynchronises; only local blocks change."""
    edited = one_mib[:500_000] + seeded_bytes("triage-edit", 1000) + one_mib[501_000:]
    comparison = fuzzy_compare(one_mib_signature, fuzzy_hash_bytes(edited))
    assert comparison.score > 60


def test_completely_different_buffers_score_low(one_mib: bytes, one_mib_signature: str) -> None:
    """Two independent 1 MiB buffers share no window: the score collapses."""
    other = fuzzy_hash_bytes(seeded_bytes("triage-other", 1024 * 1024))
    comparison = fuzzy_compare(one_mib_signature, other)
    assert 0 <= comparison.score < 30
    assert comparison.same_file is False


# ---- block-size rules ---------------------------------------------------------


@pytest.mark.parametrize(
    ("length", "expected"),
    [
        (0, 32768),
        (1, 32768),
        (32768 * 64, 32768),
        (32768 * 64 + 1, 65536),
        (1024 * 1024, 32768),
        (32768 * 64 * 2, 65536),
        (512 * 1024 * 1024, 1048576),
        (10**9, 1048576),
    ],
)
def test_block_size_doubles_while_sixty_four_blocks_do_not_fit(length: int, expected: int) -> None:
    assert block_size_for_length(length) == expected


def test_block_size_ladder_constants_line_up() -> None:
    assert MAX_BLOCK_SIZE == MIN_BLOCK_SIZE << (NUM_BLOCK_SIZES - 1) == 1048576


def test_block_size_helper_refuses_negative_length() -> None:
    with pytest.raises(AnalysisError, match="length"):
        block_size_for_length(-1)


def test_one_mib_uses_32768_not_16384(one_mib_signature: str) -> None:
    """The ladder doubles from 32768 while bsize*64 < length; 1 MiB stays at 32768."""
    assert one_mib_signature.split(":")[0] == "32768"


def test_four_mib_moves_up_the_ladder(four_mib_signature: str) -> None:
    block_size = int(four_mib_signature.split(":")[0])
    assert block_size == 65536
    assert block_size in {MIN_BLOCK_SIZE << shift for shift in range(NUM_BLOCK_SIZES)}


# ---- fuzzy_hash_file bounds ---------------------------------------------------


def test_max_bytes_truncates_with_honest_warning(tmp_path: Path) -> None:
    data = seeded_bytes("triage-file", 100_000)
    target = tmp_path / "sample.bin"
    target.write_bytes(data)

    result = fuzzy_hash_file(target, max_bytes=50_000)

    assert result.truncated is True
    assert result.file_size == 100_000
    assert result.hashed_bytes == 50_000
    assert result.signature == fuzzy_hash_bytes(data[:50_000])
    assert result.warnings and "max_bytes" in result.warnings[0]
    assert result.evidence.confidence is Confidence.CERTAIN


def test_max_bytes_below_bounds_is_a_typed_error(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(seeded_bytes("bounds", 16))
    with pytest.raises(AnalysisError, match="max_bytes"):
        fuzzy_hash_file(target, max_bytes=0)
    with pytest.raises(AnalysisError, match="max_bytes"):
        fuzzy_hash_file(target, max_bytes=-5)


def test_fuzzy_hash_file_rejects_missing_and_directory(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="cannot stat"):
        fuzzy_hash_file(tmp_path / "missing.bin")
    with pytest.raises(AnalysisError, match="not a regular file"):
        fuzzy_hash_file(tmp_path)


def test_fuzzy_hash_bytes_rejects_empty_input() -> None:
    with pytest.raises(AnalysisError, match="empty"):
        fuzzy_hash_bytes(b"")


# ---- fuzzy_compare input handling ---------------------------------------------


def test_malformed_signatures_name_the_argument(one_mib_signature: str) -> None:
    with pytest.raises(AnalysisError, match="signature_a"):
        fuzzy_compare("nonsense", one_mib_signature)
    with pytest.raises(AnalysisError, match="signature_b"):
        fuzzy_compare(one_mib_signature, "32768:not base64:aa")
    with pytest.raises(AnalysisError, match="signature_a"):
        fuzzy_compare("32768:abc", one_mib_signature)


def test_incomparable_block_sizes_score_zero_not_error() -> None:
    first = f"32768:{varied_text('i1')}:{varied_text('i2')}"
    second = f"131072:{varied_text('i1')}:{varied_text('i2')}"
    comparison = fuzzy_compare(first, second)
    assert comparison.score == 0
    assert comparison.same_file is False


def test_factor_two_block_sizes_compare_on_the_shared_half() -> None:
    shared = varied_text("shared")
    first = f"65536:{shared}:{varied_text('f2')}"
    second = f"32768:{varied_text('s1')}:{shared}"
    comparison = fuzzy_compare(first, second)
    assert comparison.score == 100


# ---- imphash ------------------------------------------------------------------


def make_pe_with_one_import(path: Path) -> Path:
    """Write a minimal PE32+ whose import table holds exactly KERNEL32!CreateFileW.

    The module name is stored without an extension on purpose: the Mandiant
    convention digests the library string exactly as the import table stores
    it, so the fixture controls the digest input ("kernel32.createfilew").
    """
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 14, 0,
        0x200, 0, 0, 0x1000, 0x1000,
        0x140000000, 0x1000, 0x200,
        6, 0, 6, 0, 4, 0,
        0, 0x2000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    assert len(optional) == 112
    directories = bytearray(128)
    struct.pack_into("<II", directories, 8, 0x1000, 0x28)  # IMAGE_DIRECTORY_ENTRY_IMPORT
    section = struct.pack(
        "<8sIIIIIIHHI", b".idata", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + bytes(directories) + section
    headers += bytes(0x200 - len(headers))
    body = bytearray(0x200)
    struct.pack_into("<IIIII", body, 0x000, 0x1040, 0, 0, 0x1060, 0x1050)
    struct.pack_into("<II", body, 0x040, 0x1070, 0)
    struct.pack_into("<II", body, 0x050, 0x1070, 0)
    body[0x060 : 0x060 + len(b"KERNEL32\x00")] = b"KERNEL32\x00"
    hint_name = struct.pack("<H", 0) + b"CreateFileW\x00\x00"
    body[0x070 : 0x070 + len(hint_name)] = hint_name
    path.write_bytes(headers + bytes(body))
    return path


@pytest.fixture
def pe_one_import(tmp_path: Path) -> Path:
    return make_pe_with_one_import(tmp_path / "one_import.exe")


def test_import_hash_matches_the_mandiant_md5(pe_one_import: Path) -> None:
    expected = hashlib.md5(b"kernel32.createfilew").hexdigest()
    result = import_hash(pe_one_import)
    assert result.imphash == expected
    assert result.digest_input == "kernel32.createfilew"
    assert result.import_count == 1
    assert result.skipped_unnamed == 0
    assert result.truncated is False
    assert result.evidence.source == "triage.import_hash"
    assert result.evidence.method == "mandiant_convention"
    assert result.evidence.confidence is Confidence.CERTAIN


def test_import_hash_refuses_elf(elf64_text_path: Path) -> None:
    with pytest.raises(AnalysisError, match="ELF"):
        import_hash(elf64_text_path)


def test_import_hash_skips_ordinal_imports_honestly() -> None:
    info = BinaryInfo(
        path=Path("synthetic.exe"),
        format="PE",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=None,
        image_base=0,
        sha256="",
        file_size=0,
        imports=[
            ImportInfo(name="ordinal_3", library="KERNEL32"),
            ImportInfo(name="CreateFileW", library="KERNEL32"),
            ImportInfo(name="NoLibraryPairing", library=None),
        ],
    )
    result = _import_hash_from_info(info)
    assert result.digest_input == "kernel32.createfilew"
    assert result.skipped_unnamed == 2
    assert result.import_count == 1


def test_import_hash_bounds_the_digest_input() -> None:
    info = BinaryInfo(
        path=Path("synthetic.exe"),
        format="PE",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=None,
        image_base=0,
        sha256="",
        file_size=0,
        imports=[
            ImportInfo(name=f"Func{i}", library="KERNEL32") for i in range(MAX_IMPORTS + 500)
        ],
    )
    result = _import_hash_from_info(info)
    assert result.import_count == MAX_IMPORTS
    assert result.truncated is True
    assert result.digest_input.count(",") == MAX_IMPORTS - 1


def test_import_hash_refuses_pe_without_named_imports() -> None:
    info = BinaryInfo(
        path=Path("ordinal_only.exe"),
        format="PE",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        entry_point=None,
        image_base=0,
        sha256="",
        file_size=0,
        imports=[ImportInfo(name="ordinal_1", library="KERNEL32")],
    )
    with pytest.raises(AnalysisError, match="no named imports"):
        _import_hash_from_info(info)


# ---- composite report ---------------------------------------------------------


def test_triage_hashes_composes_everything_on_the_pe(pe_one_import: Path) -> None:
    report = triage_hashes(pe_one_import)
    payload = report.to_dict()

    assert report.format == "PE"
    assert report.architecture == "x86_64"
    assert report.sha256 == hashlib.sha256(pe_one_import.read_bytes()).hexdigest()
    assert report.size == pe_one_import.stat().st_size
    assert report.imphash is not None
    assert report.imphash.imphash == hashlib.md5(b"kernel32.createfilew").hexdigest()
    assert report.fuzzy.signature == fuzzy_hash_bytes(pe_one_import.read_bytes())
    assert report.evidence.source == "triage.report"
    assert json.loads(json.dumps(payload)) == payload


def test_triage_hashes_degrades_imphash_on_elf(elf64_text_path: Path) -> None:
    report = triage_hashes(elf64_text_path)

    assert report.imphash is None
    assert any("no imphash" in warning for warning in report.warnings)
    assert report.fuzzy.signature == fuzzy_hash_bytes(elf64_text_path.read_bytes())
    assert json.loads(json.dumps(report.to_dict())) == report.to_dict()


# ---- CLI ------------------------------------------------------------------------


def test_cli_triage_table_and_compare(elf64_text_path: Path, tmp_path: Path) -> None:
    """`codevanta triage` hashes a binary and scores a --compare twin."""
    import shutil

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    twin = tmp_path / "twin.bin"
    shutil.copyfile(elf64_text_path, twin)
    result = runner.invoke(cli, ["triage", str(elf64_text_path), "--compare", str(twin)])
    assert result.exit_code == 0, result.output
    assert "score 100/100" in result.output
    assert "fuzzy" in result.output


def test_cli_triage_missing_file_exits_2(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["triage", str(tmp_path / "missing.bin")])
    assert result.exit_code == 2

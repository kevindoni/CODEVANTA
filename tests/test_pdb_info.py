"""Tests for the pure-stdlib PDB information parser.

All MSF and PE inputs are synthetic fixtures assembled byte by byte below —
no real PDB files and no network access are involved anywhere.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis.pdb_info import (
    DbiModule,
    codeview_reference,
    decode_codeview_record,
    parse_pdb,
)
from codevanta.core.report import AnalysisError

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

BLOCK_SIZE = 512
MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
GUID_BYTES = bytes(range(16))
GUID_TEXT = "03020100-0504-0706-0809-0a0b0c0d0e0f"
INFO_VERSION = 20091201
INFO_SIGNATURE = 0x53445352
INFO_AGE = 7
NAMES_SIGNATURE = 0xEF_FE_EF_FE  # 0xeffeeffe


def make_module_record(imod: int, name: bytes, obj: bytes) -> bytes:
    """One DBI module record: 64-byte prefix + module name + object name."""
    prefix = bytearray(64)
    struct.pack_into("<H", prefix, 20, imod)  # module index, verified at +20
    record = bytes(prefix) + name + b"\x00" + obj + b"\x00"
    return record + b"\x00" * (-len(record) % 4)


def make_dbi_stream(records: list[bytes]) -> bytes:
    """One DBI stream: 64-byte header + module-info substream."""
    body = b"".join(records)
    header = bytearray(64)
    struct.pack_into("<i", header, 0, -1)
    struct.pack_into("<i", header, 4, 19990903)
    struct.pack_into("<I", header, 8, 1)
    struct.pack_into("<I", header, 24, len(body))
    return bytes(header) + body


NAMED_STREAMS_BLOB = b"/names\x00/linkinfo\x00"


def make_info_stream(named_blob: bytes = NAMED_STREAMS_BLOB) -> bytes:
    """One PDB info stream: header + inline named-stream blob (u32 size)."""
    return (
        struct.pack("<III", INFO_VERSION, INFO_SIGNATURE, INFO_AGE)
        + GUID_BYTES
        + struct.pack("<I", len(named_blob))
        + named_blob
    )


def make_names_stream(names: list[bytes]) -> bytes:
    """One ``/names`` stream: magic, hash version, length-prefixed string blob."""
    blob = b"\x01" + b"".join(name + b"\x00" for name in names)
    return struct.pack("<III", NAMES_SIGNATURE, 1, len(blob)) + blob


def build_msf(
    *,
    info: bytes | None = None,
    names: bytes | None = None,
    dbi: bytes | None = None,
) -> bytes:
    """Assemble a minimal MSF v7.00 file out of 512-byte blocks.

    Layout: block 0 superblock, block 1 block map, block 2 the stream
    directory (single block), then streams 1 (info), 2 (names) and 3 (DBI)
    spanning as many whole blocks as each needs; stream 0 is declared empty.
    """
    if info is None:
        info = make_info_stream()
    if names is None:
        names = make_names_stream([b"/names", b"/linkinfo"])
    if dbi is None:
        dbi = make_dbi_stream(
            [
                make_module_record(1, b"app.obj", b"C:\\build\\app.obj"),
                make_module_record(2, b"lib.obj", b"C:\\build\\lib.obj"),
            ]
        )
    payloads = [b"", info, names, dbi]
    spans = [-(-len(payload) // BLOCK_SIZE) for payload in payloads]
    next_block = 3
    placements: list[list[int]] = []
    for span in spans:
        placements.append(list(range(next_block, next_block + span)))
        next_block += span
    num_blocks = next_block

    directory = struct.pack("<I", len(payloads))
    for payload in payloads:
        directory += struct.pack("<I", len(payload))
    for placed in placements:
        for block in placed:
            directory += struct.pack("<I", block)
    assert len(directory) <= BLOCK_SIZE

    blocks = [bytearray(BLOCK_SIZE) for _ in range(num_blocks)]
    blocks[0][: len(MSF_MAGIC)] = MSF_MAGIC
    struct.pack_into("<6I", blocks[0], 32, BLOCK_SIZE, 1, num_blocks, len(directory), 0, 1)
    struct.pack_into("<I", blocks[1], 0, 2)
    blocks[2][: len(directory)] = directory
    for payload, placed in zip(payloads, placements, strict=True):
        for i in range(0, len(payload), BLOCK_SIZE):
            block = placed[i // BLOCK_SIZE]
            chunk = payload[i : i + BLOCK_SIZE]
            blocks[block][: len(chunk)] = chunk
    return b"".join(bytes(block) for block in blocks)


def write_msf(tmp_path: Path, **kwargs: bytes | None) -> tuple[Path, bytes]:
    """Write a synthetic MSF file and return (path, file bytes)."""
    blob = build_msf(**kwargs)
    target = tmp_path / "mini.pdb"
    target.write_bytes(blob)
    return target, blob


# ---- MSF structural walk ------------------------------------------------------


def test_parse_minimal_msf(tmp_path: Path) -> None:
    target, blob = write_msf(tmp_path)
    report = parse_pdb(target)

    assert report.block_size == 512
    assert report.num_blocks == 6
    assert report.stream_count == 4
    assert [stream.index for stream in report.streams] == [0, 1, 2, 3]
    assert report.streams[0].size == 0
    assert report.streams[0].blocks == 0
    assert report.streams[1].size == 49  # 28-byte header + u32 size + 17-byte blob
    assert report.streams[1].blocks == 1
    assert report.sha256 == hashlib.sha256(blob).hexdigest()
    assert report.truncated is False
    assert report.warnings == ()
    assert report.evidence.source == "pdb.info"
    assert report.evidence.method == "msf_walk"
    assert report.evidence.confidence.value == "certain"


def test_parse_info_stream_guid_age_version(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    report = parse_pdb(target)

    assert report.guid == GUID_TEXT
    assert report.age == INFO_AGE
    assert report.pdb_version == INFO_VERSION
    assert report.evidence.extra["signature"] == f"0x{INFO_SIGNATURE:08x}"


def test_parse_stream_names(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    report = parse_pdb(target)

    assert report.names_stream_index == 2
    assert report.stream_names == ("/names", "/linkinfo")
    assert report.streams[2].name == "/names"
    assert report.streams[1].name is None
    assert report.streams[2].blocks == 1


def test_names_binding_requires_stream_magic(tmp_path: Path) -> None:
    names = struct.pack("<III", 0xDEADBEEF, 1, 0)
    target, _ = write_msf(tmp_path, names=names)
    report = parse_pdb(target)

    assert report.names_stream_index is None
    assert all(stream.name is None for stream in report.streams)
    assert report.stream_names == ("/names", "/linkinfo")


def test_parse_dbi_modules(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    report = parse_pdb(target)

    assert report.modules == (
        DbiModule(index=0, module_name="app.obj", object_name="C:\\build\\app.obj"),
        DbiModule(index=1, module_name="lib.obj", object_name="C:\\build\\lib.obj"),
    )
    assert report.module_count == 2


# ---- superblock / directory error paths ---------------------------------------


def test_wrong_magic(tmp_path: Path) -> None:
    target, blob = write_msf(tmp_path)
    corrupt = bytearray(blob)
    corrupt[0:4] = b"XXXX"
    target.write_bytes(bytes(corrupt))
    with pytest.raises(AnalysisError, match="magic"):
        parse_pdb(target)


def test_insane_block_sizes(tmp_path: Path) -> None:
    for bad in (256, 1000, 32768):
        target, blob = write_msf(tmp_path)
        corrupt = bytearray(blob)
        struct.pack_into("<I", corrupt, 32, bad)
        target.write_bytes(bytes(corrupt))
        with pytest.raises(AnalysisError, match="block size"):
            parse_pdb(target)


def test_directory_block_map_points_outside(tmp_path: Path) -> None:
    target, blob = write_msf(tmp_path)
    corrupt = bytearray(blob)
    struct.pack_into("<I", corrupt, BLOCK_SIZE, 999)
    target.write_bytes(bytes(corrupt))
    with pytest.raises(AnalysisError, match="outside"):
        parse_pdb(target)


def test_stream_block_points_outside(tmp_path: Path) -> None:
    target, blob = write_msf(tmp_path)
    corrupt = bytearray(blob)
    stream1_block_entry = 2 * BLOCK_SIZE + 4 + 16  # count + four sizes
    struct.pack_into("<I", corrupt, stream1_block_entry, 1234)
    target.write_bytes(bytes(corrupt))
    with pytest.raises(AnalysisError, match="outside"):
        parse_pdb(target)


def test_truncated_and_missing_files(tmp_path: Path) -> None:
    short = tmp_path / "short.pdb"
    short.write_bytes(MSF_MAGIC[:24])
    with pytest.raises(AnalysisError, match="truncated"):
        parse_pdb(short)
    with pytest.raises(AnalysisError, match="cannot stat"):
        parse_pdb(tmp_path / "missing.pdb")


# ---- honest bounds ------------------------------------------------------------


def test_max_streams_truncates_rows_not_total(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    report = parse_pdb(target, max_streams=2)

    assert report.stream_count == 4
    assert len(report.streams) == 2
    assert report.truncated is True
    assert any("capped at 2 of 4" in warning for warning in report.warnings)


def test_max_modules_truncates_rows(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    report = parse_pdb(target, max_modules=1)

    assert report.module_count == 1
    assert len(report.modules) == 1
    assert report.modules[0].module_name == "app.obj"
    assert report.truncated is True
    assert any("module cap 1" in warning for warning in report.warnings)


def test_names_cap_is_reported(tmp_path: Path) -> None:
    blob = b"".join(f"n{i}\x00".encode() for i in range(4100))
    info = make_info_stream(named_blob=blob)
    target, _ = write_msf(tmp_path, info=info)
    report = parse_pdb(target)

    assert len(report.stream_names) == 4096
    assert report.stream_names[0] == "n0"
    assert report.truncated is True
    assert any("names cap 4096" in warning for warning in report.warnings)


def test_absent_names_stream_index_warns(tmp_path: Path) -> None:
    info = (
        struct.pack("<III", INFO_VERSION, INFO_SIGNATURE, INFO_AGE)
        + GUID_BYTES
        + struct.pack("<I", 512)  # claims 512 bytes of names, none exist
    )
    target, _ = write_msf(tmp_path, info=info)
    report = parse_pdb(target)

    assert report.stream_names == ()
    assert any("claims 512 bytes but only 0 exist" in w for w in report.warnings)


def test_desynced_dbi_walk_names_the_module_index(tmp_path: Path) -> None:
    prefix = bytearray(64)
    struct.pack_into("<H", prefix, 20, 1)
    broken = (
        bytes(prefix)
        + b"app.obj\x00"
        + b"C:\\build\\app.obj"  # no NUL terminator: the walk must stop, not guess
    )
    target, _ = write_msf(tmp_path, dbi=make_dbi_stream([broken]))
    report = parse_pdb(target)

    assert report.modules == ()
    assert any("desynchronized at module index 0" in warning for warning in report.warnings)
    assert report.truncated is True


# ---- JSON safety and determinism ----------------------------------------------


def test_report_is_json_safe_and_deterministic(tmp_path: Path) -> None:
    target, _ = write_msf(tmp_path)
    first = parse_pdb(target)
    second = parse_pdb(target)

    assert first == second
    payload = json.dumps(first.to_dict())
    assert json.loads(payload) == first.to_dict()
    assert payload == json.dumps(second.to_dict())


# ---- CodeView record decoder --------------------------------------------------


def test_decode_rsds_record() -> None:
    blob = b"RSDS" + GUID_BYTES + struct.pack("<I", 3) + b"D:\\src\\app.pdb\x00trailing"
    reference = decode_codeview_record(blob)

    assert reference.debug_type == "RSDS"
    assert reference.guid == GUID_TEXT
    assert reference.age == 3
    assert reference.pdb_path == "D:\\src\\app.pdb"
    assert reference.timestamp is None
    assert reference.evidence.confidence.value == "certain"


def test_decode_nb10_record() -> None:
    blob = b"NB10" + struct.pack("<III", 1, 0x11223344, 7) + b"c:\\x.pdb\x00"
    reference = decode_codeview_record(blob)

    assert reference.debug_type == "NB10"
    assert reference.guid is None
    assert reference.timestamp == 0x11223344
    assert reference.age == 7
    assert reference.pdb_path == "c:\\x.pdb"


def test_decode_unknown_and_truncated_records() -> None:
    with pytest.raises(AnalysisError, match="unknown CodeView signature"):
        decode_codeview_record(b"MTOC" + b"\x00" * 16)
    with pytest.raises(AnalysisError, match="RSDS record truncated"):
        decode_codeview_record(b"RSDS" + b"\x00" * 10)
    with pytest.raises(AnalysisError, match="too small"):
        decode_codeview_record(b"RS")


# ---- codeview_reference over PE fixtures --------------------------------------

PDB_PATH = b"D:\\src\\app.pdb"
RSDS_RECORD = b"RSDS" + GUID_BYTES + struct.pack("<I", 3) + PDB_PATH + b"\x00"


def make_pe64_with_rsds(path: Path) -> Path:
    """Hand-assemble a minimal PE32+ with one section and one RSDS debug entry.

    File layout: 0x400 bytes of headers, then ``.rdata`` (RVA 0x1000) holding
    the RSDS record followed by the 28-byte IMAGE_DEBUG_DIRECTORY entry.
    """
    record_offset = 0x400
    rdata = RSDS_RECORD + struct.pack(
        "<IIHHIIII",
        0,  # characteristics
        0,  # time date stamp
        0,  # major version
        0,  # minor version
        2,  # type = IMAGE_DEBUG_TYPE_CODEVIEW
        len(RSDS_RECORD),
        0x1000,  # AddressOfRawData (RVA of the record)
        record_offset,  # PointerToRawData
    )
    debug_dir_rva = 0x1000 + len(RSDS_RECORD)

    headers = bytearray(0x400)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    pe = 0x80
    headers[pe : pe + 4] = b"PE\x00\x00"
    coff = pe + 4
    struct.pack_into(
        "<HHIIIHH",
        headers,
        coff,
        0x8664,  # machine = AMD64
        1,  # number of sections
        0,
        0,
        0,
        240,  # size of optional header
        0x0022,  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    optional = coff + 20
    struct.pack_into("<H", headers, optional, 0x20B)  # PE32+ magic
    struct.pack_into("<Q", headers, optional + 24, 0x140000000)  # image base
    struct.pack_into("<I", headers, optional + 28, 0x1000)  # section alignment
    struct.pack_into("<I", headers, optional + 32, 0x200)  # file alignment
    struct.pack_into("<I", headers, optional + 56, 0x2000)  # size of image
    struct.pack_into("<I", headers, optional + 60, 0x400)  # size of headers
    struct.pack_into("<I", headers, optional + 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", headers, optional + 112 + 6 * 8, debug_dir_rva, 28)

    section_table = optional + 240
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        section_table,
        b".rdata",
        len(rdata),  # virtual size
        0x1000,  # virtual address
        len(rdata),  # size of raw data
        record_offset,  # pointer to raw data
        0,
        0,
        0,
        0,
        0x40000040,  # INITIALIZED_DATA | READ
    )
    path.write_bytes(bytes(headers) + rdata)
    return path


def test_codeview_reference_from_synthetic_pe(tmp_path: Path) -> None:
    pe = make_pe64_with_rsds(tmp_path / "rsds.exe")
    reference = codeview_reference(pe)

    assert reference is not None
    assert reference.debug_type == "RSDS"
    assert reference.guid == GUID_TEXT
    assert reference.age == 3
    assert reference.pdb_path == "D:\\src\\app.pdb"
    assert reference.section == ".rdata"
    assert reference.evidence.method == "debug_directory"
    assert reference.evidence.confidence.value == "certain"
    assert json.dumps(reference.to_dict())


def test_codeview_reference_none_without_debug_directory(tmp_path: Path) -> None:
    sample = SAMPLES / "pe64_text.bin"
    if not sample.is_file():  # pragma: no cover - committed sample
        pytest.skip("samples/pe64_text.bin not present")
    assert codeview_reference(sample) is None


def test_codeview_reference_rejects_non_pe(tmp_path: Path) -> None:
    elf = SAMPLES / "elf64_text.bin"
    if not elf.is_file():  # pragma: no cover - committed sample
        pytest.skip("samples/elf64_text.bin not present")
    with pytest.raises(AnalysisError, match="not a PE file"):
        codeview_reference(elf)
    with pytest.raises(AnalysisError, match="file not found"):
        codeview_reference(tmp_path / "nope.exe")


# ---- CLI ------------------------------------------------------------------------


def test_cli_pdb_codeview_mode_and_error(tmp_path: Path) -> None:
    """`codevanta pdb` on a non-PDB PE-shaped file reports CodeView absence."""
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    plain = tmp_path / "notes.txt"
    plain.write_text("hi", encoding="utf-8")
    result = runner.invoke(cli, ["pdb", str(plain)])
    assert result.exit_code == 2


def test_cli_pdb_json_on_synthetic_pdb(tmp_path: Path) -> None:
    import json as _json

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    sample, _ = write_msf(tmp_path)
    result = runner.invoke(cli, ["pdb", str(sample), "--json"])
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["mode"] == "pdb"

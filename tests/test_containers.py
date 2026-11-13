"""Binary-container lane tests: parsers, CLI wiring and MCP tools.

Every fixture is assembled byte by byte in this module, so the tests stay
offline and self-contained: a synthetic WASM module (type/import/export/code
sections), a valid and a truncated EVM program, a GGUF v2 file with a typed
kv block and an array value, a safetensors header, little-endian pcap and
pcapng captures, a firmware image stuffed with known magics, and a real
SQLite database created through :mod:`sqlite3` in a temp dir. What is
asserted is every extracted field, the ``None``-on-magic-miss contract, the
typed ``AnalysisError`` for malformed input, and the CLI/MCP wiring only --
the parsers have their guarantees, the CLI/MCP layers just have to reach
them.
"""

from __future__ import annotations

import json
import re
import sqlite3
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from codevanta.analysis import containers
from codevanta.analysis.containers import (
    MAX_EVM_OPS,
    inspect_container,
    inspect_evm,
    inspect_gguf,
    inspect_pcap,
    inspect_safetensors,
    inspect_wasm,
    load_container_bytes,
    require_evm,
    scan_magics,
)
from codevanta.analysis.sqlite_view import inspect_sqlite
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

runner = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal escape sequences from ``text``, keeping its layout."""
    return _ANSI_ESCAPE.sub("", text)


def _output(result: Result) -> str:
    """Return stdout and stderr merged, ANSI-stripped and whitespace-flattened."""
    stderr = getattr(result, "stderr", "") or ""
    return " ".join(_plain(f"{result.stdout} {stderr}").split())


def _payload(result: Result) -> dict:
    """Return the parsed JSON object printed by a ``--json`` option."""
    text = _plain(result.stdout)
    return json.loads(text[text.index("{") : text.rindex("}") + 1])


def _pack(*parts: bytes | int) -> bytes:
    """Little-endian pack helper keeping the fixtures readable."""
    out = bytearray()
    for part in parts:
        if isinstance(part, int):
            out += part.to_bytes(_int_width(part), "little")
        else:
            out += part
    return bytes(out)


def _int_width(value: int) -> int:
    """Smallest little-endian width that round-trips ``value`` (1/2/4/8)."""
    if 0 <= value < 0x100:
        return 1
    if 0 <= value < 0x10000:
        return 2
    if 0 <= value < 0x1_0000_0000:
        return 4
    return 8


# --- 8< --- fixtures ---


def wasm_path(tmp_path: Path) -> Path:
    """A minimal WASM module: type, one function import, one export, code."""
    sections = (
        b"\x01\x05\x01\x60\x00\x01\x7f"  # type: one () -> i32
        b"\x02\x07\x01\x01\x65\x01\x66\x00\x00"  # import: e.f = func 0
        b"\x07\x06\x01\x02\x6f\x6b\x00\x00"  # export: "ok" -> func 0
        b"\x0a\x04\x01\x02\x00\x0b"  # code: one empty body ending in end
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(b"\x00asm\x01\x00\x00\x00" + sections)
    return target


VALID_EVM = bytes.fromhex("6003565b00")  # PUSH1 3; JUMP; JUMPDEST(3); STOP

def gguf_bytes() -> bytes:
    """GGUF v2: one tensor, a string kv and a u32-array kv, padded to 32."""
    def gguf_string(text: bytes) -> bytes:
        return struct.pack("<Q", len(text)) + text

    head = b"GGUF" + struct.pack("<IQQ", 2, 1, 2)
    kv1 = gguf_string(b"general.architecture") + struct.pack("<I", 8) + gguf_string(b"llama")
    kv2 = (
        gguf_string(b"test.arr")
        + struct.pack("<I", 9)  # array
        + struct.pack("<I", 4)  # of u32
        + struct.pack("<Q", 3)  # count
        + struct.pack("<3I", 7, 8, 9)
    )
    tensor = (
        gguf_string(b"blk.0.weight")
        + struct.pack("<I", 1)
        + struct.pack("<Q", 2)
        + struct.pack("<IQ", 0, 0)  # F32, data offset 0
    )
    end = len(head + kv1 + kv2 + tensor)
    pad = (-end) % 32
    return head + kv1 + kv2 + tensor + b"\x00" * pad + b"WEIGHTS" * 4


def safetensors_bytes() -> bytes:
    """safetensors: one F32 2x2 tensor, one metadata key, 16 payload bytes."""
    header = {
        "__metadata__": {"source": "test"},
        "w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
    }
    blob = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<Q", len(blob)) + blob + b"\x00" * 16


def pcap_bytes() -> bytes:
    """Little-endian pcap 2.4, linktype 1, one 4-byte packet at ts 1700000000.5."""
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet = struct.pack("<IIII", 1700000000, 500000, 4, 4) + b"\xde\xad\xbe\xef"
    return head + packet


def pcapng_bytes() -> bytes:
    """pcapng: SHB, IDB (linktype 1, snaplen 65535) and one EPB with ts 1.0."""
    shb = struct.pack(
        "<IIIHHQI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF, 28
    )
    idb = struct.pack("<IIHHII", 0x00000001, 20, 1, 0, 65535, 20)
    epb = struct.pack("<IIIIIII", 0x00000006, 32, 0, 0, 1000000, 0, 0) + struct.pack("<I", 32)
    return shb + idb + epb


def firmware_bytes() -> bytes:
    """A firmware image with gzip, squashfs and DTB magics at aligned offsets."""
    blob = bytearray(2048)
    blob[0:3] = b"\x1f\x8b\x08"
    blob[512:516] = b"hsqs"
    blob[1024:1028] = b"\xd0\x0d\xfe\xed"
    return bytes(blob)


def sqlite_db_path(tmp_path: Path) -> Path:
    """A real two-table database built through stdlib sqlite3 in ``tmp_path``."""
    target = tmp_path / "app.db"
    connection = sqlite3.connect(target)
    try:
        connection.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        connection.execute("CREATE TABLE meta (key TEXT, value BLOB)")
        connection.execute("INSERT INTO items VALUES (1, 'alpha'), (2, 'beta')")
        connection.execute("INSERT INTO meta VALUES ('blob', X'00FF10')")
        connection.commit()
    finally:
        connection.close()
    return target


# --- 8< --- WASM ---


def test_wasm_summary_decodes_sections_and_counts(tmp_path: Path) -> None:
    summary = inspect_wasm(wasm_path(tmp_path).read_bytes())
    assert summary is not None
    assert summary.version == 1
    assert [section.name for section in summary.sections] == [
        "type",
        "import",
        "export",
        "code",
    ]
    assert summary.section_count == 4
    assert summary.import_count == 1
    assert summary.export_count == 1
    assert not summary.truncated
    assert summary.sections[1].offset == 15
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.wasm"
    payload = summary.to_dict()
    json.dumps(payload)  # JSON-safe
    assert payload["sections"][0]["name"] == "type"


def test_wasm_rejects_wrong_magic() -> None:
    assert inspect_wasm(b"\x7fELF...") is None
    assert inspect_wasm(b"\x00as") is None


def test_wasm_truncated_section_table_sets_truncated(tmp_path: Path) -> None:
    data = b"\x00asm\x01\x00\x00\x00" + b"\x01\x20\x01\x60\x00\x00"
    summary = inspect_wasm(data)
    assert summary is not None
    assert summary.truncated
    assert any("past the end" in warning for warning in summary.warnings)


# --- 8< --- EVM ---


def test_evm_sweep_lists_ops_and_validates_jump_targets() -> None:
    summary = inspect_evm(VALID_EVM)
    assert summary is not None
    assert [(op.pc, op.op) for op in summary.ops] == [
        (0, "PUSH1"),
        (2, "JUMP"),
        (3, "JUMPDEST"),
        (4, "STOP"),
    ]
    assert summary.ops[0].operand == "0x03"
    assert summary.jumpdest_positions == (3,)
    assert summary.jump_targets_total == 1
    assert summary.jump_targets_valid == 1
    assert summary.evm_like
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.evm"
    assert summary.evidence.confidence.value == "medium"
    json.dumps(summary.to_dict())


def test_evm_push_data_bytes_are_not_jumpdests() -> None:
    # PUSH32 carrying 0x5b bytes: none of them is an instruction start.
    summary = inspect_evm(bytes.fromhex("7f") + b"\x5b" * 32 + bytes.fromhex("5b00"))
    assert summary is not None
    assert summary.jumpdest_positions == (33,)


def test_evm_undecodable_byte_stops_the_sweep() -> None:
    summary = inspect_evm(b"\x00\x0c\x01")
    assert summary is not None
    assert summary.invalid_at == 1
    assert not summary.evm_like
    assert any("undecodable" in warning for warning in summary.warnings)


def test_evm_bounded_op_list() -> None:
    summary = inspect_evm(b"\x00" * 300)
    assert summary is not None
    assert summary.op_count == MAX_EVM_OPS
    assert summary.truncated
    assert any("bounded" in warning for warning in summary.warnings)


def test_evm_no_decodable_ops_returns_none() -> None:
    assert inspect_evm(b"\x0c\x0c") is None
    assert inspect_evm(b"") is None


def test_require_evm_maps_bad_input_to_typed_error() -> None:
    with pytest.raises(AnalysisError):
        require_evm(b"\x0c\x0c")
    with pytest.raises(AnalysisError):
        require_evm(b"hello world")


# --- 8< --- GGUF ---


def test_gguf_header_kv_and_aligned_data_offset() -> None:
    data = gguf_bytes()
    summary = inspect_gguf(data)
    assert summary is not None
    assert summary.version == 2
    assert summary.tensor_count == 1
    assert summary.kv_count == 2
    assert summary.kv[0]["key"] == "general.architecture"
    assert summary.kv[0]["value"] == "llama"
    assert summary.kv[1]["type"] == "array"
    assert summary.kv[1]["element_type"] == "u32"
    assert summary.kv[1]["count"] == 3
    assert summary.tensor_names == ("blk.0.weight:F32",)
    assert summary.data_offset == (len(data) - len(b"WEIGHTS" * 4) + 31) // 32 * 32
    assert not summary.kv_truncated
    assert not summary.tensors_truncated
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.gguf"
    json.dumps(summary.to_dict())


def test_gguf_rejects_wrong_magic_and_version() -> None:
    assert inspect_gguf(b"NOPE" + b"\x00" * 20) is None
    data = b"GGUF" + struct.pack("<IQQ", 1, 0, 0) + b"\x00" * 16
    assert inspect_gguf(data) is None


def test_gguf_truncated_body_degrades_to_warning() -> None:
    # Chopping 40 bytes cuts into the tensor-info table, past the kv block.
    summary = inspect_gguf(gguf_bytes()[:-40])
    assert summary is not None
    assert summary.tensors_truncated
    assert summary.data_offset is None
    assert summary.warnings


# --- 8< --- safetensors ---


def test_safetensors_header_decodes_tensors_and_metadata() -> None:
    summary = inspect_safetensors(safetensors_bytes())
    assert summary is not None
    assert summary.tensor_count == 1
    assert summary.metadata_keys == 1
    tensor = summary.tensors[0]
    assert tensor.name == "w"
    assert tensor.dtype == "F32"
    assert tensor.shape == (2, 2)
    assert (tensor.start, tensor.end) == (0, 16)
    assert summary.total_tensor_bytes == 16
    assert summary.payload_bytes == 16
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.safetensors"
    json.dumps(summary.to_dict())


def test_safetensors_rejects_non_json_header() -> None:
    bad = struct.pack("<Q", 4) + b"nope" + b"\x00" * 4
    assert inspect_safetensors(bad) is None
    assert inspect_safetensors(b"\x00" * 8) is None


# --- 8< --- pcap / pcapng ---


def test_pcap_global_header_and_packet_walk() -> None:
    summary = inspect_pcap(pcap_bytes())
    assert summary is not None
    assert summary.format == "pcap"
    assert summary.endian == "little"
    assert (summary.version_major, summary.version_minor) == (2, 4)
    assert summary.snaplen == 65535
    assert summary.linktype == 1
    assert summary.linktype_name == "EN10MB"
    assert summary.record_count == 1
    assert summary.first_timestamp == 1700000000.5
    assert not summary.truncated
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.pcap"
    json.dumps(summary.to_dict())


def test_pcap_rejects_wrong_magic() -> None:
    assert inspect_pcap(b"\x00" * 32) is None
    assert inspect_pcap(b"MZ" + b"\x00" * 30) is None


def test_pcap_truncated_final_record_sets_truncated() -> None:
    summary = inspect_pcap(pcap_bytes()[:-4])
    assert summary is not None
    assert summary.truncated
    assert any("truncated" in warning for warning in summary.warnings)


def test_pcapng_block_walk_names_blocks_and_reads_timestamp() -> None:
    summary = inspect_pcap(pcapng_bytes())
    assert summary is not None
    assert summary.format == "pcapng"
    assert summary.version_major == 1
    assert summary.block_types == ("SHB", "IDB", "EPB")
    assert summary.record_count == 1
    assert summary.first_timestamp == 1.0
    assert summary.linktype == 1
    assert summary.snaplen == 65535
    assert summary.evidence is not None
    assert summary.evidence.method == "pcapng_block_walk"


# --- 8< --- firmware magic scan ---


def test_magic_scan_reports_offsets_kinds_and_alignment() -> None:
    summary = scan_magics(firmware_bytes())
    assert summary is not None
    by_kind = {hit.kind: hit for hit in summary.hits}
    assert set(by_kind) == {"gzip", "squashfs", "dtb"}
    assert by_kind["gzip"].offset == 0
    assert by_kind["gzip"].aligned
    assert by_kind["gzip"].confidence == "low"
    assert by_kind["squashfs"].offset == 512
    assert by_kind["squashfs"].confidence == "medium"
    assert by_kind["dtb"].offset == 1024
    assert summary.hit_count == 3
    assert summary.evidence is not None
    assert summary.evidence.source == "bin.magics"
    json.dumps(summary.to_dict())


def test_magic_scan_no_hits_returns_none() -> None:
    assert scan_magics(b"\xde\xad" * 16) is None


def test_magic_scan_bounded_hits() -> None:
    data = b"\x1f\x8b\x08" * 100  # gzip magic every 3 bytes, skip step 1
    summary = scan_magics(data)
    assert summary is not None
    assert summary.hit_count == containers.MAX_MAGIC_HITS
    assert summary.truncated


# --- 8< --- binmeta auto-detection ---


def test_binmeta_detects_wasm_and_runs_magic_sweep(tmp_path: Path) -> None:
    module = wasm_path(tmp_path).read_bytes()
    target = tmp_path / "mod.wasm"
    target.write_bytes(module + b"\x1f\x8b\x08trailer")
    summary = inspect_container(target)
    assert summary.detected == ("wasm",)
    assert summary.wasm is not None
    assert summary.magics is not None
    assert summary.magics.hits[0].kind == "gzip"
    assert summary.magics.hits[0].offset == len(module)
    assert any(item.source == "bin.wasm" for item in summary.evidence)
    json.dumps(summary.to_dict())


def test_binmeta_detects_gguf_safetensors_pcap_evm(tmp_path: Path) -> None:
    cases: list[tuple[bytes, str]] = [
        (gguf_bytes(), "gguf"),
        (safetensors_bytes(), "safetensors"),
        (pcap_bytes(), "pcap"),
        (pcapng_bytes(), "pcap"),
        (VALID_EVM, "evm"),
    ]
    for index, (data, expected) in enumerate(cases):
        target = tmp_path / f"case{index}.bin"
        target.write_bytes(data)
        summary = inspect_container(target)
        assert summary.detected == (expected,), expected
        assert summary.size_bytes == len(data)


def test_binmeta_matches_nothing_is_not_an_error(tmp_path: Path) -> None:
    target = tmp_path / "garbage.bin"
    target.write_bytes(b"\xde\xad\xbe\xef" * 8)
    summary = inspect_container(target)
    assert summary.detected == ()
    assert any("no container format matched" in warning for warning in summary.warnings)


def test_load_container_bytes_typed_errors(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        load_container_bytes(tmp_path / "missing.bin")
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * 16)
    monkey_max = 8
    original = containers.MAX_FILE_BYTES
    containers.MAX_FILE_BYTES = monkey_max
    try:
        with pytest.raises(AnalysisError):
            load_container_bytes(big)
    finally:
        containers.MAX_FILE_BYTES = original


# --- 8< --- SQLite introspection ---


def test_sqlite_lists_tables_with_row_counts(tmp_path: Path) -> None:
    summary = inspect_sqlite(sqlite_db_path(tmp_path))
    assert summary.table_count == 2
    assert [entry.name for entry in summary.tables] == ["items", "meta"]
    assert summary.tables[0].row_count == 2
    assert summary.tables[1].row_count == 1
    assert not summary.truncated
    assert not summary.wal_present
    assert summary.immutable_mode
    assert summary.evidence is not None
    assert summary.evidence.method == "sqlite_ro_immutable"
    payload = summary.to_dict()
    json.dumps(payload)
    assert payload["tables"][0]["row_count"] == 2


def test_sqlite_table_schema_and_sample_rows(tmp_path: Path) -> None:
    summary = inspect_sqlite(sqlite_db_path(tmp_path), table="items")
    assert summary.requested_table == "items"
    entry = summary.tables[0]
    assert [(column.name, column.type, column.primary_key) for column in entry.columns] == [
        ("id", "INTEGER", True),
        ("name", "TEXT", False),
    ]
    assert entry.sample_rows[0]["name"] == "alpha"
    assert len(entry.sample_rows) == 2


def test_sqlite_blob_values_are_json_safe(tmp_path: Path) -> None:
    summary = inspect_sqlite(sqlite_db_path(tmp_path), table="meta")
    value = summary.tables[0].sample_rows[0]["value"]
    assert value == "<blob 3 bytes>"
    json.dumps(summary.to_dict())


def test_sqlite_notes_wal_without_touching_it(tmp_path: Path) -> None:
    db = sqlite_db_path(tmp_path)
    db.with_name(db.name + "-wal").write_bytes(b"")  # present-but-ignored WAL
    summary = inspect_sqlite(db)
    assert summary.wal_present
    assert summary.shm_present is False
    assert any("WAL" in warning for warning in summary.warnings)


def test_sqlite_typed_errors(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        inspect_sqlite(tmp_path / "missing.db")
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"definitely not a database" * 4)
    with pytest.raises(AnalysisError):
        inspect_sqlite(junk)
    db = sqlite_db_path(tmp_path)
    with pytest.raises(AnalysisError):
        inspect_sqlite(db, table="nope")


# --- 8< --- CLI wiring ---


def test_cli_binmeta_json(tmp_path: Path) -> None:
    target = tmp_path / "mod.wasm"
    target.write_bytes(wasm_path(tmp_path).read_bytes())
    result = runner.invoke(app, ["binmeta", str(target), "--json"])
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["detected"] == ["wasm"]
    assert payload["wasm"]["import_count"] == 1
    assert any(item["source"] == "bin.wasm" for item in payload["evidence"])


def test_cli_binmeta_table_and_no_match(tmp_path: Path) -> None:
    target = tmp_path / "mod.wasm"
    target.write_bytes(wasm_path(tmp_path).read_bytes())
    result = runner.invoke(app, ["binmeta", str(target)])
    assert result.exit_code == 0, _output(result)
    out = _output(result)
    assert "WASM v1 section table" in out
    assert "imports: 1" in out
    assert "evidence: bin.wasm" in out
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\xde\xad\xbe\xef" * 8)
    result = runner.invoke(app, ["binmeta", str(junk)])
    assert result.exit_code == 0
    assert "no container format matched" in _output(result)


def test_cli_binmeta_missing_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["binmeta", str(tmp_path / "gone.bin")])
    assert result.exit_code == 2
    assert "error:" in _output(result)


def test_cli_evm_json_and_table(tmp_path: Path) -> None:
    target = tmp_path / "code.evm"
    target.write_bytes(VALID_EVM)
    result = runner.invoke(app, ["evm", str(target), "--json"])
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["evm_like"] is True
    assert payload["jump_targets_valid"] == 1
    assert payload["ops"][0]["op"] == "PUSH1"
    result = runner.invoke(app, ["evm", str(target)])
    assert result.exit_code == 0
    out = _output(result)
    assert "JUMPDEST" in out
    assert "jump targets: 1/1 valid" in out
    assert "evidence: bin.evm" in out


def test_cli_evm_rejects_undecodable_bytes(tmp_path: Path) -> None:
    target = tmp_path / "bad.evm"
    target.write_bytes(b"\x0c\x0c")
    result = runner.invoke(app, ["evm", str(target)])
    assert result.exit_code == 2
    assert "error:" in _output(result)


def test_cli_sqlite_json_table_and_errors(tmp_path: Path) -> None:
    db = sqlite_db_path(tmp_path)
    result = runner.invoke(app, ["sqlite", str(db), "--json"])
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert [entry["name"] for entry in payload["tables"]] == ["items", "meta"]
    result = runner.invoke(app, ["sqlite", str(db), "--table", "items", "--json"])
    assert result.exit_code == 0, _output(result)
    payload = _payload(result)
    assert payload["requested_table"] == "items"
    assert payload["tables"][0]["sample_rows"][0]["name"] == "alpha"
    result = runner.invoke(app, ["sqlite", str(db)])
    assert result.exit_code == 0
    assert "evidence: bin.sqlite" in _output(result)
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 4)
    result = runner.invoke(app, ["sqlite", str(junk)])
    assert result.exit_code == 2
    assert "error:" in _output(result)


# --- 8< --- MCP tool layer ---


def test_mcp_binmeta_and_sqlite(tmp_path: Path) -> None:
    payload = tools.codevanta_binmeta(str(wasm_path(tmp_path)))
    assert payload["detected"] == ["wasm"]
    assert payload["evidence"][0]["source"] == "bin.wasm"
    db = sqlite_db_path(tmp_path)
    assert tools.codevanta_sqlite(str(db))["table_count"] == 2
    payload = tools.codevanta_sqlite(str(db), table="items")
    assert payload["requested_table"] == "items"
    assert payload["tables"][0]["row_count"] == 2


def test_mcp_binmeta_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        tools.codevanta_binmeta(str(tmp_path / "missing.bin"))
    with pytest.raises(AnalysisError):
        tools.codevanta_sqlite(str(tmp_path / "missing.db"))


def test_mcp_tools_module_exports_bin_tools() -> None:
    assert callable(tools.codevanta_binmeta)
    assert callable(tools.codevanta_sqlite)

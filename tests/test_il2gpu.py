"""Offline tests for the IL2CPP and GPU depth lanes."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis.gpu_meta import GpuCodeSummary, _parse_cob, inspect_gpu
from codevanta.analysis.il2cpp_meta import parse_il2cpp_meta
from codevanta.cli.il2gpu import app as il2gpu_app
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError

runner = CliRunner()


def _il2cpp_v29_fixture(tmp_path: Path, size: int = 256) -> Path:
    data = bytearray(size)
    struct.pack_into("<II", data, 0, 0xFAB11BAF, 29)
    pairs = [(16, 64), (96, 32), (200, 200), (0, 0), (0, 0), (0, 0)]
    for i, (offset, table_size) in enumerate(pairs):
        struct.pack_into("<II", data, 8 + i * 8, offset, table_size)
    path = tmp_path / "global-metadata.dat"
    path.write_bytes(bytes(data))
    return path


def _fatbin_fixture(tmp_path: Path) -> Path:
    payload = b"//" + b"\n" + b".sm_86" + b"\n" + b".visible .entry kernel() { }" + b"\n"
    entry = (
        struct.pack("<HHIQ", 2, 1, 16, len(payload))
        + bytes([0] * 8)
        + payload
    )
    data = (
        struct.pack("<I", 0xBA55ED50)
        + struct.pack("<HHQ", 1, 16, len(entry))
        + entry
    )
    path = tmp_path / "kernel.fatbin"
    path.write_bytes(data)
    return path


def _cob_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "bundle.cob"
    path.write_bytes(b"device: gfx1100\nhost: x86_64-pc-linux\nmore\n")
    return path


def _minimal_elf64_cubin() -> bytes:
    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0]) + bytes(8)
    strtab = bytes([0]) + b".nv.info" + bytes([0]) + b".shstrtab" + bytes([0])
    nv_info = b";%PTX .entry kernel()" + bytes([0x0A])
    sh0 = bytes(64)
    sh1 = struct.pack("<IIQQQQIIQQ", 1, 1, 0, 0, 64 + len(strtab), len(nv_info), 0, 0, 0, 0)
    sh2 = struct.pack("<IIQQQQIIQQ", 10, 3, 0, 0, 64, len(strtab), 0, 0, 0, 0)
    str_off = 64
    nv_off = str_off + len(strtab)
    sh_off = nv_off + len(nv_info)
    sections = sh0 + sh1 + sh2
    header = ident + struct.pack("<HHIQQQIHHHHHH", 1, 126, 1, 0, 0, sh_off, 0, 64, 0, 0, 64, 3, 2)
    pad = bytes((sh_off - (nv_off + len(nv_info))) % 8)
    return header + strtab + nv_info + pad + sections
def test_il2cpp_v29_header_pairs(tmp_path: Path) -> None:
    path = _il2cpp_v29_fixture(tmp_path)
    summary = parse_il2cpp_meta(path)
    assert summary.version == 29
    assert summary.family == "29"
    assert summary.tables[0].name == "string-literals"
    assert summary.tables[0].count == 8
    assert any("overruns" in warning for warning in summary.warnings)
    assert json.loads(json.dumps(summary.to_dict())) == summary.to_dict()


def test_il2cpp_bad_magic_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.dat"
    path.write_bytes(bytes(64))
    with pytest.raises(AnalysisError):
        parse_il2cpp_meta(path)


def test_fatbin_entries_and_arch(tmp_path: Path) -> None:
    path = _fatbin_fixture(tmp_path)
    summary = inspect_gpu(path)
    assert summary.kind == "cuda-fatbin"
    assert summary.entries[0].kind == "ptx"
    assert summary.entries[0].arch == "sm_86"
    assert "sm_86" in summary.evidence.to_dict()["extra"]["archs"]


def test_fatbin_bad_entry_header_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.fatbin"
    data = (
        struct.pack("<I", 0xBA55ED50)
        + struct.pack("<HHQ", 1, 16, 32)
        + struct.pack("<HHIQ", 2, 1, 8, 16)
        + bytes(40)
    )
    path.write_bytes(data)
    with pytest.raises(AnalysisError):
        inspect_gpu(path)


def test_cob_bundle(tmp_path: Path) -> None:
    path = _cob_fixture(tmp_path)
    summary = inspect_gpu(path)
    assert summary.kind == "cob"
    assert len(summary.entries) == 2
    with pytest.raises(AnalysisError):
        _parse_cob(bytes(16))


def test_cubin_sections_and_ptx() -> None:
    summary = inspect_gpu_bytes(_minimal_elf64_cubin())
    assert summary.kind == "cubin"
    assert any(entry.kind == ".nv.info" for entry in summary.entries)


def inspect_gpu_bytes(data: bytes) -> GpuCodeSummary:
    from codevanta.analysis.gpu_meta import inspect_gpu_data

    return inspect_gpu_data(data)


def test_inspect_gpu_unrecognized(tmp_path: Path) -> None:
    path = tmp_path / "junk.bin"
    path.write_bytes(bytes([0xDE, 0xAD, 0xBE, 0xEF]) + bytes(64))
    with pytest.raises(AnalysisError):
        inspect_gpu(path)


def test_cli_il2cpp_and_gpu(tmp_path: Path) -> None:
    meta = _il2cpp_v29_fixture(tmp_path)
    fatbin = _fatbin_fixture(tmp_path)
    listed = runner.invoke(il2gpu_app, ["il2cpp", str(meta), "--format", "json"])
    assert listed.exit_code == 0, listed.output
    payload = json.loads(listed.output)
    assert payload["version"] == 29
    shown = runner.invoke(il2gpu_app, ["gpu", str(fatbin), "--format", "json"])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.output)["kind"] == "cuda-fatbin"


def test_cli_providers_registered() -> None:
    result = runner.invoke(app, ["providers", "--format", "json"])
    assert result.exit_code == 0, result.output

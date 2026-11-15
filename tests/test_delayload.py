"""PE delay-load import decoder tests (lane-dload).

All fixtures are hand-built PE32+ images written to ``tmp_path`` -- no real
binaries, no network, no external tools. Malformed cases prove the typed
:class:`~codevanta.core.report.AnalysisError`; the MCP
``codevanta_delayload`` tool is exercised against the same bytes.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from codevanta.analysis import delayload
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools

SECTION_VA = 0x1000

OPT_SIZE = {0x20B: 240, 0x10B: 224}


def _align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def make_pe(
    path: Path,
    *,
    opt_magic: int = 0x20B,
    data_dirs: dict[int, tuple[int, int]] | None = None,
    section_payload: bytes = b"",
    section_va: int = 0x1000,
    num_dirs: int = 16,
) -> Path:
    """Build a minimal PE with one section carrying ``section_payload``.

    RVAs are the file-offset-equivalent ``section_va + payload offset``
    (identity mapping), so callers can point a data directory at any byte
    they place in the payload.
    """
    data_dirs = data_dirs or {}
    opt_size = OPT_SIZE[opt_magic]
    num_sections = 1  # always emit the section table entry (even when empty)
    headers_size = 0x80 + 24 + opt_size + 40 * num_sections
    headers_size = _align(headers_size, 16)
    payload_off = headers_size

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = bytearray(24)
    coff[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", coff, 4, 0x8664, num_sections, 0, 0, 0, opt_size, 0x0022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    struct.pack_into("<I", opt, 16, section_va + 0x10)  # entry point
    struct.pack_into("<H", opt, 70, 0x0640)  # DllCharacteristics NX|DYNAMIC_BASE
    struct.pack_into("<I", opt, 92 if opt_magic == 0x10B else 108, num_dirs)
    dd_off = 96 if opt_magic == 0x10B else 112
    for index, (rva, size) in data_dirs.items():
        struct.pack_into("<II", opt, dd_off + 8 * index, rva, size)
    section = bytearray(40)
    section[0:7] = b".didat\x00"
    struct.pack_into(
        "<IIII",
        section, 8,
        len(section_payload), section_va, len(section_payload), payload_off,
    )
    out = bytearray(dos)
    out += coff
    out += opt
    out += section
    out += bytes(headers_size - len(out))
    out += section_payload
    path.write_bytes(bytes(out))
    return path


def _hint_name(hint: int, name: str) -> bytes:
    """One ``IMAGE_IMPORT_BY_NAME``: hint WORD + NUL-terminated ASCII name."""
    return struct.pack("<H", hint) + name.encode("ascii") + b"\x00"


def _v1_fixture() -> tuple[bytes, dict[int, tuple[int, int]]]:
    """One ImgDelayDescr v1 (dlattrRva set) + INT with 2 imports + NULL."""
    int_off = 0x20
    hn0_off = 0x2C
    hn1_off = 0x34
    name_off = 0x3C
    hmod_off = 0x48
    int_rva = SECTION_VA + int_off
    descriptor = struct.pack(
        "<IIIIIIII",
        0x1,  # grAttrs: dlattrRva
        SECTION_VA + name_off,  # szName
        SECTION_VA + hmod_off,  # pHmod
        int_rva,  # pIAT
        int_rva,  # pINT
        0,  # pBound
        0,  # pUnload
        0,  # dwTimeStamp
    )
    int_table = struct.pack("<III", SECTION_VA + hn0_off, SECTION_VA + hn1_off, 0)
    payload = (
        descriptor
        + int_table
        + _hint_name(1, "Foo")
        + b"\x00\x00"  # pad to 0x34
        + _hint_name(2, "Bar")
        + b"\x00\x00"  # pad to 0x3C
        + b"SHELL32.dll\x00"
        + b"\x00\x00\x00\x00"  # hmod slot
    )
    assert len(payload) == 0x4C
    return payload, {13: (SECTION_VA, 32)}


def _v2_fixture() -> tuple[bytes, dict[int, tuple[int, int]]]:
    """One 64-byte ImgDelayDescr v2 (dlattrRva + CFG check bit), u64 thunks."""
    int_off = 0x40
    hn0_off = 0x58
    hn1_off = 0x60
    name_off = 0x68
    hmod_off = 0x74
    int_rva = SECTION_VA + int_off
    descriptor = struct.pack(
        "<IIQQQQQQQ",
        0x1 | delayload.DLATTR_CF_CHECK,  # grAttrs: dlattrRva | cf-check
        0,  # v2 alignment pad
        SECTION_VA + name_off,  # szName
        SECTION_VA + hmod_off,  # pHmod
        int_rva,  # pIAT
        int_rva,  # pINT
        0,  # pBound
        0,  # pUnload
        0,  # qwTimeStamp
    )
    int_table = struct.pack(
        "<QQQ", SECTION_VA + hn0_off, SECTION_VA + hn1_off, 0
    )
    payload = (
        descriptor
        + int_table
        + _hint_name(1, "Foo")
        + b"\x00\x00"  # pad to 0x60
        + _hint_name(2, "Bar")
        + b"\x00\x00"  # pad to 0x68
        + b"USER32.dll\x00"
        + b"\x00"  # pad to 0x74
        + b"\x00" * 8  # hmod slot
    )
    assert len(payload) == 0x7C
    return payload, {13: (SECTION_VA, 64)}


# ---- decode tests ---------------------------------------------------------------


def test_v1_descriptor_decodes_two_imports(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    target = make_pe(tmp_path / "v1.exe", data_dirs=dirs, section_payload=payload)
    summary = delayload.inspect_delay_loads(target)
    assert summary.delay_load_present is True
    assert summary.descriptor_count == 1
    assert summary.import_count == summary.import_total == 2
    assert summary.warnings == ()
    descriptor = summary.descriptors[0]
    assert descriptor["dll_name"] == "SHELL32.dll"
    assert descriptor["gr_attrs"] == 0x1
    assert descriptor["gr_attr_names"] == ["rva"]
    assert descriptor["version"] == "v1"
    assert descriptor["int_rva"] == SECTION_VA + 0x20
    assert descriptor["iat_rva"] == SECTION_VA + 0x20
    assert descriptor["imports"] == ["Foo", "Bar"]
    assert descriptor["import_total"] == 2
    assert descriptor["imports_truncated"] is False
    assert summary.evidence.source == "pe.delayload"
    assert summary.evidence.confidence.value == "high"


def test_v2_descriptor_decodes_with_cfg_check_bit(tmp_path: Path) -> None:
    payload, dirs = _v2_fixture()
    target = make_pe(tmp_path / "v2.exe", data_dirs=dirs, section_payload=payload)
    summary = delayload.inspect_delay_loads(target)
    assert summary.delay_load_present is True
    descriptor = summary.descriptors[0]
    assert descriptor["version"] == "v2"
    assert descriptor["dll_name"] == "USER32.dll"
    assert descriptor["gr_attrs"] == 0x1 | delayload.DLATTR_CF_CHECK
    assert descriptor["gr_attr_names"] == ["rva", "cf-check"]
    assert descriptor["imports"] == ["Foo", "Bar"]


def test_unmapped_name_rva_raises_typed_error(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    descriptor = bytearray(payload[:32])
    struct.pack_into("<I", descriptor, 4, SECTION_VA + len(payload) + 0x100)
    payload = bytes(descriptor) + payload[32:]
    target = make_pe(tmp_path / "badname.exe", data_dirs=dirs, section_payload=payload)
    with pytest.raises(AnalysisError, match="DLL name RVA .* is not mapped"):
        delayload.inspect_delay_loads(target)


def test_truncated_descriptor_raises_typed_error(tmp_path: Path) -> None:
    payload, _dirs = _v1_fixture()
    target = make_pe(
        tmp_path / "short.exe", data_dirs={13: (SECTION_VA, 16)}, section_payload=payload
    )
    with pytest.raises(AnalysisError, match="delay-load descriptor truncated"):
        delayload.inspect_delay_loads(target)


def test_bind_time_va_descriptor_warns_but_decodes(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    descriptor = bytearray(payload[:32])
    struct.pack_into("<I", descriptor, 0, 0)  # grAttrs: no dlattrRva
    payload = bytes(descriptor) + payload[32:]
    target = make_pe(tmp_path / "va.exe", data_dirs=dirs, section_payload=payload)
    summary = delayload.inspect_delay_loads(target)
    assert summary.descriptors[0]["gr_attrs"] == 0
    assert summary.descriptors[0]["imports"] == ["Foo", "Bar"]
    assert any("dlattrRva" in warning for warning in summary.warnings)


def test_ordinal_import_reports_hash_name(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    int_table = struct.pack("<III", 0x80000007, SECTION_VA + 0x2C, 0)
    payload = payload[:32] + int_table + payload[0x2C:]
    target = make_pe(tmp_path / "ordinal.exe", data_dirs=dirs, section_payload=payload)
    summary = delayload.inspect_delay_loads(target)
    assert summary.descriptors[0]["imports"] == ["#7", "Foo"]


def test_no_delay_directory_reports_present_false(tmp_path: Path) -> None:
    target = make_pe(tmp_path / "plain.exe")
    summary = delayload.inspect_delay_loads(target)
    assert summary.delay_load_present is False
    assert summary.descriptor_count == 0
    assert summary.descriptors == ()
    assert summary.import_total == 0
    assert summary.evidence.method == "data-directory-13-empty"


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        delayload.inspect_delay_loads(tmp_path / "ghost.exe")


def test_decode_is_deterministic(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    target = make_pe(tmp_path / "det.exe", data_dirs=dirs, section_payload=payload)
    assert delayload.inspect_delay_loads(target).to_dict() == (
        delayload.inspect_delay_loads(target).to_dict()
    )


# ---- MCP surface ----------------------------------------------------------------


def test_mcp_delayload_tool(tmp_path: Path) -> None:
    payload, dirs = _v1_fixture()
    target = make_pe(tmp_path / "mcp.exe", data_dirs=dirs, section_payload=payload)
    result = tools.codevanta_delayload(str(target))
    assert result["delay_load_present"] is True
    assert result["descriptors"][0]["dll_name"] == "SHELL32.dll"
    assert result["import_total"] == 2
    with pytest.raises(AnalysisError, match="file not found"):
        tools.codevanta_delayload(str(tmp_path / "ghost.exe"))


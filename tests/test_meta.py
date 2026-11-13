"""Format-metadata inspector tests (lane-meta).

All fixtures are synthetic bytes built in-test; nothing touches the
network, the filesystem beyond ``tmp_path``, or real binaries.
"""

from __future__ import annotations

import asyncio
import json
import struct
import zipfile
import zlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis import binmeta
from codevanta.analysis.binmeta import (
    APK_SIG_BLOCK_MAGIC,
    ELECTRON_FUSE_SENTINEL,
    GO_BUILDINFO_MAGIC,
    MAX_CARGO_CRATES,
    MAX_GO_DEPS,
    detect_apk_signing,
    detect_cargo_auditable,
    detect_desktop_app,
    detect_electron_fuses,
    detect_elf_notes,
    detect_go_buildinfo,
    detect_kernel_module,
    detect_pyc,
    inspect_metadata,
)
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

runner = CliRunner()


def _lp32(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def _elf64(
    path: Path,
    *,
    e_type: int = 2,
    phdrs: list[tuple[int, int, bytes]] | None = None,
    sections: list[tuple[str, int, bytes]] | None = None,
) -> Path:
    """Build a synthetic ELF64 file with identity VA mapping.

    ``phdrs`` entries are ``(p_type, p_flags, content)``; content lands in
    the data area and the program header maps offset==vaddr. ``sections``
    entries are ``(name, sh_type, content)``.
    """
    phdrs = phdrs or []
    sections = sections or []
    data_off = 64 + 56 * len(phdrs)
    ph_entries: list[bytes] = []
    blob = bytearray()
    placed: list[tuple[str, int, int]] = []  # (name, sh_type, offset)
    for p_type, p_flags, content in phdrs:
        while len(blob) % 8:
            blob.append(0)
        offset = data_off + len(blob)
        blob += content
        ph_entries.append(
            struct.pack(
                "<IIQQQQQQ",
                p_type, p_flags, offset, offset, 0, len(content), len(content), 0,
            )
        )
    for name, sh_type, content in sections:
        while len(blob) % 8:
            blob.append(0)
        placed.append((name, sh_type, data_off + len(blob), len(content)))
        blob += content
    shstr = bytearray(b"\0")
    names: dict[str, int] = {}
    for name, _, _, _ in placed:
        names[name] = len(shstr)
        shstr += name.encode("ascii") + b"\0"
    names[".shstrtab"] = len(shstr)
    shstr += b".shstrtab\0"
    shstr_off = data_off + len(blob)
    shoff = shstr_off + len(shstr)
    while shoff % 8:
        shoff += 1
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, 62, 1, 0, 64, shoff, 0, 64, 56, len(phdrs),
        64, len(placed) + 2, len(placed) + 1,
    )
    out = bytearray(ehdr)
    for entry in ph_entries:
        out += entry
    out += blob
    out += shstr
    while len(out) % 8:
        out.append(0)
    out += bytes(64)  # null section header
    for name, sh_type, offset, size in placed:
        out += struct.pack(
            "<IIQQQQIIQQ",
            names[name], sh_type, 0, 0, offset, size, 0, 0, 1, 0,
        )
    out += struct.pack(
        "<IIQQQQIIQQ",
        names[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0,
    )
    path.write_bytes(bytes(out))
    return path


def _note(name_with_nul: bytes, n_type: int, desc: bytes) -> bytes:
    """One aligned ELF note record (``name_with_nul`` includes its NUL)."""
    blob = bytearray(struct.pack("<III", len(name_with_nul), len(desc), n_type))
    blob += name_with_nul
    while len(blob) % 4:
        blob.append(0)
    blob += desc
    while len(blob) % 4:
        blob.append(0)
    return bytes(blob)


def _go_mod(deps: int = 2, replacement: bool = True) -> str:
    lines = ["mod\texample.com/app\tv1.0.0"]
    for idx in range(deps):
        lines.append(f"dep\texample.com/dep{idx}\tv1.{idx}.0")
    if replacement:
        # Go records a replacement as its own "=>" line after the dep line.
        lines.append("dep\told.example/lib\tv1.2.3")
        lines.append("=>\tnew.example/lib\tv1.2.4")
    lines.append("build\t-compiler=gc")
    return "\n".join(lines)


APK_BLOCK_ID_V2 = 0x7109871A
APK_BLOCK_ID_V3 = 0xF05368C0


def _apk_digest_record(alg: int, digest: bytes) -> bytes:
    return struct.pack("<III", 8 + len(digest), alg, len(digest)) + digest


def _apk_signer(sd: bytes) -> bytes:
    return _lp32(sd) + _lp32(b"SIGS") + _lp32(b"PUBKEY")


def _apk_signers(signers: list[bytes]) -> bytes:
    return _lp32(b"".join(_lp32(s) for s in signers))


def build_apk(
    path: Path,
    *,
    with_v2: bool = True,
    with_v3: bool = True,
    with_v1: bool = True,
) -> Path:
    """Write a synthetic APK: real zip + inserted APK Signing Block."""
    with zipfile.ZipFile(path, "w") as archive:
        if with_v1:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        archive.writestr("classes.dex", b"dex-bytes\n")
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = int.from_bytes(data[eocd + 16 : eocd + 20], "little")
    digests = _apk_digest_record(0x0105, b"\x11" * 32)
    sd_v2 = _lp32(digests) + _lp32(b"CERTS") + _lp32(b"ATTRS")
    sd_v3 = sd_v2 + struct.pack("<II", 24, 34)
    pairs = b""
    if with_v2:
        signers = _apk_signers([_apk_signer(sd_v2)])
        pairs += (
            struct.pack("<Q", 4 + len(signers))
            + struct.pack("<I", APK_BLOCK_ID_V2)
            + signers
        )
    if with_v3:
        signers = _apk_signers([_apk_signer(sd_v3)])
        pairs += (
            struct.pack("<Q", 4 + len(signers))
            + struct.pack("<I", APK_BLOCK_ID_V3)
            + signers
        )
    size = len(pairs) + 24
    if not pairs:
        path.write_bytes(bytes(data))
        return path
    block = (
        struct.pack("<Q", size)
        + pairs
        + struct.pack("<Q", size)
        + APK_SIG_BLOCK_MAGIC
    )
    out = bytearray(data[:cd_off] + block + data[cd_off:])
    eocd2 = bytes(out).rfind(b"PK\x05\x06")
    out[eocd2 + 16 : eocd2 + 20] = (cd_off + len(block)).to_bytes(4, "little")
    path.write_bytes(bytes(out))
    return path


def build_fuses(
    path: Path,
    *,
    states: bytes = b"111010011",
    version: int = 1,
    truncate: bool = False,
) -> Path:
    blob = b"MZ" + bytes(24) + ELECTRON_FUSE_SENTINEL
    blob += bytes([version, len(states)]) + states
    if truncate:
        blob = blob[:-2]
    path.write_bytes(blob)
    return path


def pyc_bytes(
    *, magic: int = 3495, flags: int = 0, tail: bytes | None = None
) -> bytes:
    if tail is None:
        tail = struct.pack("<II", 1_700_000_000, 1234)
    return struct.pack("<H", magic) + b"\r\n" + struct.pack("<I", flags) + tail


def pe_with_clr(clr: bool) -> bytes:
    """Minimal PE32+ with (or without) a non-zero CLR data-directory entry."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x80)
    out = bytearray(dos)
    out += bytes(0x80 - len(out))
    out += b"PE\0\0"
    out += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    opt[0:2] = struct.pack("<H", 0x20B)
    opt[24:32] = struct.pack("<Q", 0x140000000)
    opt[108:112] = struct.pack("<I", 16)
    if clr:
        opt[112 + 14 * 8 : 112 + 14 * 8 + 4] = struct.pack("<I", 0x2000)
    out += opt
    return bytes(out)


# ---- .pyc ---------------------------------------------------------------------


def test_pyc_timestamp_based(tmp_path: Path) -> None:
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    info = detect_pyc(p)
    assert info is not None
    assert info.magic == 3495
    assert info.python_version == "3.11"
    assert info.flags == 0
    assert info.hash_based is False
    assert info.check_source is False
    assert info.timestamp == 1_700_000_000
    assert info.source_size == 1234
    assert info.source_hash is None
    assert info.evidence.source == "meta.pyc"
    assert info.evidence.confidence.value == "high"


def test_pyc_hash_based(tmp_path: Path) -> None:
    p = tmp_path / "hashed.pyc"
    p.write_bytes(pyc_bytes(flags=3, tail=bytes(range(8))))
    info = detect_pyc(p)
    assert info is not None
    assert info.hash_based is True
    assert info.check_source is True
    assert info.source_hash == bytes(range(8))
    assert info.timestamp is None
    assert info.source_size is None


def test_pyc_unknown_magic_is_medium(tmp_path: Path) -> None:
    p = tmp_path / "future.pyc"
    p.write_bytes(pyc_bytes(magic=3550))
    info = detect_pyc(p)
    assert info is not None
    assert info.python_version is None


def test_pyc_truncated_header_raises(tmp_path: Path) -> None:
    p = tmp_path / "cut.pyc"
    p.write_bytes(pyc_bytes()[:8])
    with pytest.raises(AnalysisError):
        detect_pyc(p)


def test_detect_pyc_none_on_garbage(tmp_path: Path) -> None:
    p = tmp_path / "junk.bin"
    p.write_bytes(b"NOPE!" * 10)
    assert detect_pyc(p) is None


def test_inspect_pyc_report(tmp_path: Path) -> None:
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    report = inspect_metadata(p)
    assert report.kind == "python-pyc"
    assert report.details["pyc"]["magic"] == 3495
    assert report.details["pyc"]["timestamp"] == 1_700_000_000
    payload = report.to_dict()
    json.dumps(payload)  # must be JSON-safe
    assert payload["evidence"][0]["source"] == "meta.pyc"


# ---- APK signing ---------------------------------------------------------------


def test_apk_v2_v3_v1(tmp_path: Path) -> None:
    p = build_apk(tmp_path / "app.apk")
    info = detect_apk_signing(p)
    assert info is not None
    assert info.block_size is not None and info.block_size > 24
    assert info.v2_signer_count == 1
    assert info.v3_signer_count == 1
    assert "ECDSA-SHA256" in info.digest_algorithms
    assert info.min_sdk == 24
    assert info.max_sdk == 34
    assert info.v1_present is True
    assert "META-INF/CERT.SF" in info.v1_signature_files
    sources = {item.source for item in info.evidence}
    assert sources == {"meta.apk.sigblock", "meta.apk.v1"}
    report = inspect_metadata(p)
    assert report.kind == "apk-signing"


def test_apk_v1_only(tmp_path: Path) -> None:
    p = build_apk(tmp_path / "v1.apk", with_v2=False, with_v3=False)
    info = detect_apk_signing(p)
    assert info is not None
    assert info.block_size is None
    assert info.v1_present is True
    assert info.v2_signer_count is None
    assert info.v3_signer_count is None


def test_apk_block_only_no_v1(tmp_path: Path) -> None:
    p = build_apk(tmp_path / "v2only.apk", with_v1=False)
    info = detect_apk_signing(p)
    assert info is not None
    assert info.v1_present is False
    assert info.v2_signer_count == 1


def test_apk_corrupt_block_magic_falls_back_to_v1(tmp_path: Path) -> None:
    p = build_apk(tmp_path / "broken.apk")
    data = bytearray(p.read_bytes())
    idx = bytes(data).rfind(APK_SIG_BLOCK_MAGIC)
    data[idx] ^= 0xFF
    p.write_bytes(bytes(data))
    info = detect_apk_signing(p)
    assert info is not None
    assert info.block_size is None  # block no longer recognized
    assert info.v1_present is True


def test_apk_footer_size_mismatch_raises(tmp_path: Path) -> None:
    p = build_apk(tmp_path / "mismatch.apk")
    data = bytearray(p.read_bytes())
    eocd = bytes(data).rfind(b"PK\x05\x06")
    cd_off = int.from_bytes(data[eocd + 16 : eocd + 20], "little")
    declared = int.from_bytes(data[cd_off - 24 : cd_off - 16], "little")
    # The trailing size-of-block field sits directly before the magic;
    # bumping it desynchronizes it from the leading size field.
    data[cd_off - 24 : cd_off - 16] = (declared + 8).to_bytes(8, "little")
    p.write_bytes(bytes(data))
    with pytest.raises(AnalysisError):
        detect_apk_signing(p)


def test_apk_truncated_zip_raises(tmp_path: Path) -> None:
    p = tmp_path / "cut.apk"
    p.write_bytes(b"PK\x03\x04" + b"local-header-only" * 4)
    with pytest.raises(AnalysisError):
        detect_apk_signing(p)


def test_detect_apk_none_on_garbage(tmp_path: Path) -> None:
    p = tmp_path / "junk.bin"
    p.write_bytes(b"NOPE!" * 10)
    assert detect_apk_signing(p) is None


# ---- Go build info -------------------------------------------------------------


def test_go_inline_layout(tmp_path: Path) -> None:
    p = tmp_path / "app.elf"
    mod = _go_mod()
    blob = GO_BUILDINFO_MAGIC + bytes([8, 0x2]) + b"go1.22.0\0" + mod.encode() + b"\0"
    p.write_bytes(bytes(64) + b"\x7fELF" + bytes(12) + blob)
    info = detect_go_buildinfo(p)
    assert info is not None
    assert info.go_version == "go1.22.0"
    assert info.module_path == "example.com/app"
    assert info.module_version == "v1.0.0"
    assert info.dependency_count == 3  # 2 plain + 1 replacement
    assert "example.com/dep0@v1.0.0" in info.dependencies
    assert "old.example/lib@v1.2.3 => new.example/lib@v1.2.4" in info.dependencies
    assert info.build_settings_count == 1
    assert info.layout == "inline-strings"
    assert info.evidence.source == "meta.gobuildinfo"
    assert info.evidence.confidence.value == "high"
    report = inspect_metadata(p)
    assert report.kind == "go-buildinfo"
    assert report.details["go"]["go_version"] == "go1.22.0"


def test_go_pointer_layout(tmp_path: Path) -> None:
    p = tmp_path / "old.elf"
    vers = b"go1.17.13"
    mod = b"mod\texample.com/legacy\tv0.9.1\ndep\tgithub.com/x/y\tv1.0.0"
    header_off = 64 + 56  # ehdr + one phdr
    vers_off = header_off + 32
    mod_off = vers_off + len(vers) + 1
    build_header = GO_BUILDINFO_MAGIC + bytes([8, 0x0])
    build_header += struct.pack("<QQ", vers_off, mod_off)
    total = mod_off + len(mod) + 1
    phdr = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, total, total, 0)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )
    p.write_bytes(ehdr + phdr + build_header + vers + b"\0" + mod + b"\0")
    info = detect_go_buildinfo(p)
    assert info is not None
    assert info.go_version == "go1.17.13"
    assert info.module_path == "example.com/legacy"
    assert info.module_version == "v0.9.1"
    assert info.dependency_count == 1
    assert info.layout == "address-pointers"


def test_go_bad_pointer_size_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.elf"
    bad = GO_BUILDINFO_MAGIC + bytes([5, 0])
    p.write_bytes(bytes(64) + b"\x7fELF" + bytes(12) + bad)
    with pytest.raises(AnalysisError):
        detect_go_buildinfo(p)


def test_go_truncated_header_raises(tmp_path: Path) -> None:
    p = tmp_path / "cut.elf"
    p.write_bytes(GO_BUILDINFO_MAGIC + b"\x08")
    with pytest.raises(AnalysisError):
        detect_go_buildinfo(p)


def test_go_deps_bounded(tmp_path: Path) -> None:
    p = tmp_path / "many.elf"
    mod = _go_mod(deps=40, replacement=False)
    blob = GO_BUILDINFO_MAGIC + bytes([8, 0x2]) + b"go1.21.6\0" + mod.encode() + b"\0"
    p.write_bytes(bytes(64) + b"\x7fELF" + bytes(12) + blob)
    info = detect_go_buildinfo(p)
    assert info is not None
    assert info.dependency_count == 40
    assert len(info.dependencies) == MAX_GO_DEPS


def test_detect_go_none_without_magic(tmp_path: Path) -> None:
    p = tmp_path / "plain.bin"
    p.write_bytes(b"\x00" * 128)
    assert detect_go_buildinfo(p) is None


# ---- cargo-auditable -----------------------------------------------------------


def _audit_json(deps: int = 2) -> bytes:
    entries = [
        {"name": f"crate{idx}", "version": f"1.{idx}.0"} for idx in range(deps)
    ]
    return json.dumps(entries).encode()


def test_cargo_auditable_note(tmp_path: Path) -> None:
    p = tmp_path / "rustbin"
    note = _note(b"AUDITABLE\0", 0x1337, _audit_json())
    _elf64(p, phdrs=[(4, 0x4, note)])
    info = detect_cargo_auditable(p)
    assert info is not None
    assert info.crate_count == 2
    assert info.crates == ("crate0@1.0.0", "crate1@1.1.0")
    assert info.payload_origin == "note:AUDITABLE"
    assert info.compressed is False
    assert info.evidence.source == "meta.cargo-auditable"
    report = inspect_metadata(p)
    assert report.kind == "cargo-auditable"


def test_cargo_auditable_rust_audit_note(tmp_path: Path) -> None:
    p = tmp_path / "rustbin2"
    note = _note(b"rust-audit\0", 0x1337, _audit_json())
    _elf64(p, phdrs=[(4, 0x4, note)])
    info = detect_cargo_auditable(p)
    assert info is not None
    assert info.payload_origin == "note:rust-audit"


def test_cargo_auditable_zlib_payload(tmp_path: Path) -> None:
    p = tmp_path / "zlibbin"
    note = _note(b"AUDITABLE\0", 0x1337, zlib.compress(_audit_json()))
    _elf64(p, phdrs=[(4, 0x4, note)])
    info = detect_cargo_auditable(p)
    assert info is not None
    assert info.compressed is True
    assert info.crate_count == 2


def test_cargo_auditable_dep_v0_section(tmp_path: Path) -> None:
    p = tmp_path / "depv0"
    _elf64(p, sections=[(".dep-v0", 1, _audit_json())])
    info = detect_cargo_auditable(p)
    assert info is not None
    assert info.payload_origin == "section:.dep-v0"
    assert info.crate_count == 2


def test_cargo_auditable_malformed_payload_raises(tmp_path: Path) -> None:
    p = tmp_path / "badpayload"
    note = _note(b"AUDITABLE\0", 0x1337, b"definitely-not-json")
    _elf64(p, phdrs=[(4, 0x4, note)])
    with pytest.raises(AnalysisError):
        detect_cargo_auditable(p)


def test_cargo_auditable_crates_bounded(tmp_path: Path) -> None:
    p = tmp_path / "many"
    note = _note(b"AUDITABLE\0", 0x1337, _audit_json(deps=40))
    _elf64(p, phdrs=[(4, 0x4, note)])
    info = detect_cargo_auditable(p)
    assert info is not None
    assert info.crate_count == 40
    assert len(info.crates) == MAX_CARGO_CRATES


def test_detect_cargo_none_on_non_elf(tmp_path: Path) -> None:
    p = tmp_path / "plain.bin"
    p.write_bytes(b"AUDITABLE" + b"\x00" * 32)
    assert detect_cargo_auditable(p) is None


# ---- Electron fuses --------------------------------------------------------------


def test_fuses_states(tmp_path: Path) -> None:
    p = build_fuses(tmp_path / "electron.exe", states=b"101010011")
    info = detect_electron_fuses(p)
    assert info is not None
    assert info.fuse_schema_version == 1
    assert info.fuse_count == 9
    assert info.enabled == 5
    assert info.disabled == 4
    assert info.removed == 0
    assert info.fuses[0] == ("run_as_node", "on")
    assert info.fuses[1] == ("cookie_encryption", "off")
    assert info.fuses[3] == ("node_cli_inspect", "off")
    assert info.fuses[4] == ("embedded_asar_integrity_validation", "on")
    assert info.fuses[8] == ("wasm_trap_handlers", "on")
    assert info.evidence.source == "meta.fuses"
    report = inspect_metadata(p)
    assert report.kind == "electron-fuses"
    assert report.details["electron-fuses"]["fuses"][0]["name"] == "run_as_node"


def test_fuses_removed_state(tmp_path: Path) -> None:
    p = build_fuses(tmp_path / "r.exe", states=b"r11111111")
    info = detect_electron_fuses(p)
    assert info is not None
    assert info.removed == 1
    assert info.fuses[0] == ("run_as_node", "removed")


def test_fuses_unknown_schema_generic_names(tmp_path: Path) -> None:
    p = build_fuses(tmp_path / "v2.exe", version=2, states=b"1100")
    info = detect_electron_fuses(p)
    assert info is not None
    assert info.fuse_schema_version == 2
    assert info.fuses[0][0] == "fuse_0"


def test_fuses_truncated_raises(tmp_path: Path) -> None:
    p = build_fuses(tmp_path / "cut.exe", truncate=True)
    with pytest.raises(AnalysisError):
        detect_electron_fuses(p)


def test_fuses_implausible_count_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.exe"
    p.write_bytes(b"MZ" + bytes(24) + ELECTRON_FUSE_SENTINEL + bytes([1, 200]))
    with pytest.raises(AnalysisError):
        detect_electron_fuses(p)


def test_detect_fuses_none_without_sentinel(tmp_path: Path) -> None:
    p = tmp_path / "plain.exe"
    p.write_bytes(b"MZ" + bytes(64))
    assert detect_electron_fuses(p) is None


# ---- ELF notes ----------------------------------------------------------------


def test_elf_notes_from_segment_and_section(tmp_path: Path) -> None:
    p = tmp_path / "notes.elf"
    desc = bytes(range(8))
    seg_notes = _note(b"GNU\0", 3, desc) + _note(b"CORE\0", 1, b"\x01" * 272)
    sect_notes = _note(b"test\0", 0x1234, b"abcd")
    _elf64(p, phdrs=[(4, 0x4, seg_notes)], sections=[(".note.test", 7, sect_notes)])
    info = detect_elf_notes(p)
    assert info is not None
    assert info.note_count == 3
    assert info.note_segments == 1
    assert info.note_sections == 1
    assert info.build_id == desc.hex()
    assert info.notes[0].name == "GNU"
    assert info.notes[0].n_type_name == "NT_GNU_BUILD_ID"
    assert info.notes[1].name == "CORE"
    assert info.notes[1].n_type_name == "NT_PRSTATUS"
    assert info.notes[2].name == "test"
    assert info.notes[2].desc_hex == b"abcd".hex()
    assert info.evidence.source == "meta.elfnote"
    report = inspect_metadata(p)
    assert report.kind == "elf-notes"
    assert report.details["elf-notes"]["note_count"] == 3


def test_elf_notes_bounded(tmp_path: Path) -> None:
    p = tmp_path / "many.elf"
    blob = b"".join(_note(b"t\0\0\0", idx, b"\x00" * 4) for idx in range(40))
    _elf64(p, phdrs=[(4, 0x4, blob)])
    info = detect_elf_notes(p)
    assert info is not None
    assert info.note_count == binmeta.MAX_ELF_NOTES


def test_detect_elf_notes_none_on_pe(tmp_path: Path) -> None:
    p = tmp_path / "plain.exe"
    p.write_bytes(pe_with_clr(clr=False))
    assert detect_elf_notes(p) is None


# ---- kernel modules ------------------------------------------------------------


def test_kernel_module_modinfo(tmp_path: Path) -> None:
    p = tmp_path / "hello.ko"
    content = b"vermagic=5.15.0 SMP mod_unload\0license=GPL\0srcversion=ABCDEF01\0"
    _elf64(p, e_type=1, sections=[(".modinfo", 1, content)])
    info = detect_kernel_module(p)
    assert info is not None
    assert info.key_count == 3
    assert info.modinfo["vermagic"] == "5.15.0 SMP mod_unload"
    assert info.modinfo["license"] == "GPL"
    assert info.evidence.source == "meta.modinfo"
    report = inspect_metadata(p)
    assert report.kind == "kernel-module"
    assert report.details["kernel-module"]["modinfo"]["license"] == "GPL"


def test_kernel_module_requires_et_rel(tmp_path: Path) -> None:
    p = tmp_path / "notrel.ko"
    _elf64(p, e_type=2, sections=[(".modinfo", 1, b"vermagic=5.15.0\0")])
    assert detect_kernel_module(p) is None


def test_detect_kernel_module_none_without_modinfo(tmp_path: Path) -> None:
    p = tmp_path / "plain.ko"
    _elf64(p, e_type=1, sections=[(".text", 1, b"\x90")])
    assert detect_kernel_module(p) is None


# ---- desktop app classification --------------------------------------------------


def test_desktop_unity_il2cpp(tmp_path: Path) -> None:
    root = tmp_path / "MyGame"
    (root / "MyGame_Data" / "Resources").mkdir(parents=True)
    (root / "MyGame.exe").write_bytes(b"MZ-nothing")
    (root / "MyGame_Data" / "globalgamemanagers").write_bytes(b"unity")
    (root / "MyGame_Data" / "il2cpp_data" / "Metadata").mkdir(parents=True)
    (root / "MyGame_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat").write_bytes(b"m")
    (root / "GameAssembly.dll").write_bytes(b"MZ-nothing")
    info = detect_desktop_app(root)
    assert info is not None
    assert info.classification == "unity-il2cpp"
    assert "unity" in info.frameworks
    assert "il2cpp" in info.frameworks
    assert any("globalgamemanagers" in f for f in info.key_files)
    assert any("GameAssembly.dll" in f for f in info.key_files)
    report = inspect_metadata(root)
    assert report.kind == "desktop"
    assert report.details["desktop"]["classification"] == "unity-il2cpp"


def test_desktop_electron(tmp_path: Path) -> None:
    root = tmp_path / "ElectronApp"
    (root / "resources").mkdir(parents=True)
    (root / "resources" / "app.asar").write_bytes(b"asar")
    info = detect_desktop_app(root)
    assert info is not None
    assert info.classification == "electron"


def test_desktop_unreal(tmp_path: Path) -> None:
    root = tmp_path / "MyGame5"
    (root / "Content" / "Paks").mkdir(parents=True)
    (root / "Content" / "Paks" / "MyGame.pak").write_bytes(b"pak")
    info = detect_desktop_app(root)
    assert info is not None
    assert info.classification == "unreal"


def test_desktop_dotnet(tmp_path: Path) -> None:
    root = tmp_path / "NetApp"
    root.mkdir()
    (root / "App.exe").write_bytes(pe_with_clr(clr=True))
    info = detect_desktop_app(root)
    assert info is not None
    assert info.classification == "dotnet"


def test_desktop_no_match_returns_none(tmp_path: Path) -> None:
    root = tmp_path / "Empty"
    root.mkdir()
    assert detect_desktop_app(root) is None


def test_desktop_walk_depth_bounded(tmp_path: Path) -> None:
    root = tmp_path / "ElectronApp2"
    (root / "resources").mkdir(parents=True)
    (root / "resources" / "app.asar").write_bytes(b"asar")
    deep = root / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / "too-deep.asar").write_bytes(b"x")
    info = detect_desktop_app(root)
    assert info is not None
    assert info.classification == "electron"
    assert not any("too-deep" in f for f in info.key_files)


# ---- inspect_metadata error paths -------------------------------------------------


def test_inspect_unknown_format_raises(tmp_path: Path) -> None:
    p = tmp_path / "garbage.bin"
    p.write_bytes(b"\xde\xad\xbe\xef" * 64)
    with pytest.raises(AnalysisError):
        inspect_metadata(p)


def test_inspect_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        inspect_metadata(tmp_path / "missing.bin")


def test_inspect_empty_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    with pytest.raises(AnalysisError):
        inspect_metadata(p)


def test_inspect_oversized_file_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(binmeta, "MAX_FILE_BYTES", 64)
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * 128)
    with pytest.raises(AnalysisError):
        inspect_metadata(p)


def test_inspect_unsupported_dir_raises(tmp_path: Path) -> None:
    root = tmp_path / "Nothing"
    root.mkdir()
    (root / "readme.txt").write_bytes(b"hello")
    with pytest.raises(AnalysisError):
        inspect_metadata(root)


# ---- CLI ---------------------------------------------------------------------------


def test_cli_metadata_pyc(tmp_path: Path) -> None:
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    result = runner.invoke(app, ["metadata", str(p)])
    assert result.exit_code == 0, result.stdout
    assert "python-pyc" in result.stdout


def test_cli_metadata_json(tmp_path: Path) -> None:
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    result = runner.invoke(app, ["metadata", str(p), "--json"])
    assert result.exit_code == 0, result.stdout
    assert '"python-pyc"' in result.stdout


def test_cli_metadata_dir(tmp_path: Path) -> None:
    root = tmp_path / "ElectronApp"
    (root / "resources").mkdir(parents=True)
    (root / "resources" / "app.asar").write_bytes(b"asar")
    result = runner.invoke(app, ["metadata", str(root)])
    assert result.exit_code == 0, result.stdout
    assert "electron" in result.stdout


def test_cli_metadata_error_exit(tmp_path: Path) -> None:
    result = runner.invoke(app, ["metadata", str(tmp_path / "missing.bin")])
    assert result.exit_code != 0


def test_cli_metadata_garbage_exit(tmp_path: Path) -> None:
    p = tmp_path / "garbage.bin"
    p.write_bytes(b"\xde\xad\xbe\xef" * 64)
    result = runner.invoke(app, ["metadata", str(p)])
    assert result.exit_code != 0


# ---- MCP ---------------------------------------------------------------------------


def test_mcp_tools_metadata_pyc(tmp_path: Path) -> None:
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    payload = tools.codevanta_metadata(str(p))
    assert payload["kind"] == "python-pyc"
    assert payload["details"]["pyc"]["magic"] == 3495
    assert payload["evidence"][0]["source"] == "meta.pyc"


def test_mcp_tools_metadata_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        tools.codevanta_metadata(str(tmp_path / "missing.bin"))


def test_mcp_server_lists_and_calls_metadata(tmp_path: Path) -> None:
    listed = asyncio.run(build_server().list_tools())
    assert "codevanta_metadata" in [tool.name for tool in listed]
    p = tmp_path / "module.pyc"
    p.write_bytes(pyc_bytes())
    result = asyncio.run(
        build_server().call_tool("codevanta_metadata", {"path": str(p)})
    )
    structured = getattr(result, "structuredContent", None)
    if structured:
        payload = structured
    else:
        payload = json.loads(result.content[0].text)
    assert payload["kind"] == "python-pyc"


# ---- binmeta: low-level I/O guards -------------------------------------------


def test_checked_size_refuses_tiny_pyc_files(tmp_path: Path) -> None:
    """A file too small to hold a pyc magic reports ``None`` honestly."""
    p = tmp_path / "tiny.pyc"
    p.write_bytes(b"ab")
    assert detect_pyc(p) is None


def test_detectors_refuse_directories(tmp_path: Path) -> None:
    """Every path-taking detector reports ``None`` for a directory."""
    assert detect_go_buildinfo(tmp_path) is None
    assert detect_cargo_auditable(tmp_path) is None
    assert detect_electron_fuses(tmp_path) is None
    assert detect_elf_notes(tmp_path) is None
    assert detect_kernel_module(tmp_path) is None
    assert detect_apk_signing(tmp_path) is None
    assert detect_desktop_app(tmp_path / "nope.bin") is None


def test_desktop_app_rejects_plain_files(tmp_path: Path) -> None:
    """``detect_desktop_app`` only classifies directories."""
    p = tmp_path / "app.exe"
    p.write_bytes(b"whatever")
    assert detect_desktop_app(p) is None


# ---- binmeta: synthetic ELF32 / PE containers ---------------------------------


def _elf32(path: Path, *, phdrs: list[tuple[int, bytes]], shnum: int = 0) -> Path:
    """Minimal little-endian ELF32 with 32-bit program headers."""
    data_off = 52 + 32 * len(phdrs)
    blob = bytearray()
    ph_entries: list[bytes] = []
    for p_type, content in phdrs:
        offset = data_off + len(blob)
        blob += content
        ph_entries.append(
            struct.pack("<IIIIIIII", p_type, offset, offset, offset,
                        len(content), len(content), 6, 4)
        )
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
    ehdr = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        1, 3, 1, 0, 52, 0xFFFF00 if shnum else 0, 0,
        52, 32, len(phdrs), 40, shnum, 0,
    )
    out = bytearray(ehdr)
    out += b"".join(ph_entries)
    out += blob
    path.write_bytes(bytes(out))
    return path


def _note_blob(name: bytes, desc: bytes) -> bytes:
    return struct.pack("<III", len(name), len(desc), 1) + name + b"\x00" * (
        -len(name) % 4
    ) + desc + b"\x00" * (-len(desc) % 4)


def test_elf32_notes_parse_via_32_bit_layouts(tmp_path: Path) -> None:
    """ELF32 program headers and the bogus-section-table break both parse."""
    notes = (
        _note_blob(b"GNU\x00", struct.pack("<II", 3, 0x401000))
        + struct.pack("<III", 4, 64, 1)[:12]  # truncated note: entry_end > blob
        + b"\x00" * 4
    )
    path = _elf32(tmp_path / "note32.elf", phdrs=[(4, notes)], shnum=3)
    info = detect_elf_notes(path)
    assert info is not None
    assert info.note_segments == 1
    assert info.notes[0].name == "GNU"


def test_iter_notes_refuses_oversized_and_truncated_notes(tmp_path: Path) -> None:
    """Oversized name sizes and chopped descriptors break the bounded walk."""
    bad_size = struct.pack("<III", 0x7F_FF_FF, 4, 1)  # namesz way over cap
    chopped = struct.pack("<III", 4, 2000, 1) + b"\x00" * 8  # descriptor cut
    path = _elf64(
        tmp_path / "badnotes.elf",
        e_type=2,
        phdrs=[(4, 0, bad_size + chopped)],
    )
    assert detect_elf_notes(path) is None


def test_pe_containers_parse_sections_and_go_buildinfo(tmp_path: Path) -> None:
    """A synthetic PE32+ parses its section table and inline Go build info."""
    buildinf = _go_blob(
        8, 0x2, b"go1.22.1\x00mod\texample.com/mod\tv1.2.3\n\x00"
    )
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    sections = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 1, 0, 0x10, 0x200,
                           0x10, 0, 0, 0, 0)
    image = bytes(dos) + coff + bytes(opt) + sections + buildinf
    path = tmp_path / "go.exe"
    path.write_bytes(image)
    info = detect_go_buildinfo(path)
    assert info is not None
    assert info.go_version == "go1.22.1"
    assert info.module_path == "example.com/mod"
    assert info.layout == "inline-strings"
    assert info.evidence.source == "meta.gobuildinfo"


# ---- binmeta: Go buildinfo degenerate layouts ---------------------------------


def _go_blob(ptr_size: int, flags: int, payload: bytes) -> bytes:
    """Go buildinf blob: 14-byte magic, ptr-size/flags byte pair, payload."""
    return b"\xff Go buildinf:" + bytes([ptr_size, flags]) + payload


def test_go_buildinfo_header32_inline_strings(tmp_path: Path) -> None:
    """Go 1.24+ pads the header to 32 bytes before the inline strings."""
    blob = (
        _go_blob(8, 0x2, b"\x00" * 16)  # padding: near probe misses, far hits
        + b"go1.24.0\x00example.com/pad\x00"
    )
    path = tmp_path / "go24.bin"
    path.write_bytes(blob)
    info = detect_go_buildinfo(path)
    assert info is not None
    assert info.go_version == "go1.24.0"
    assert info.layout == "inline-strings-header32"


def test_go_buildinfo_module_info_blank_and_path_lines(tmp_path: Path) -> None:
    """Blank lines and a leading ``path`` line still fill the module fields."""
    mod = "\npath\texample.com/alt\ndep\tfoolib\tv1.0.0\n"
    blob = _go_blob(8, 0x2, b"go1.22.0\x00" + mod.encode("utf-8") + b"\x00")
    path = tmp_path / "gomod.bin"
    path.write_bytes(blob)
    info = detect_go_buildinfo(path)
    assert info is not None
    assert info.go_version == "go1.22.0"
    assert info.module_path == "example.com/alt"
    assert info.dependencies == ("foolib@v1.0.0",)
    assert info.dependency_count == 1


def test_go_buildinfo_truncated_pointer_fields_raise(tmp_path: Path) -> None:
    """A pointer-layout header cut short is a typed error."""
    path = tmp_path / "shortgo.bin"
    path.write_bytes(_go_blob(8, 0x0, b""))
    with pytest.raises(AnalysisError, match="truncated Go build info"):
        detect_go_buildinfo(path)


def test_go_buildinfo_unresolvable_pointers_raise(tmp_path: Path) -> None:
    """Pointer layout without a container cannot resolve addresses."""
    blob = _go_blob(8, 0x0, struct.pack("<QQ", 0x400000, 0x400100))
    path = tmp_path / "flatgo.bin"
    path.write_bytes(blob)
    with pytest.raises(AnalysisError, match="cannot be resolved"):
        detect_go_buildinfo(path)


def test_go_buildinfo_non_go_version_string_raises(tmp_path: Path) -> None:
    """A resolved version that is not ``go...`` is a typed error."""
    base = 120  # _elf64 identity mapping: content lands at vaddr 120
    head = _go_blob(8, 0x0, struct.pack("<QQ", base + 48, base + 53))
    load = head + b"\x00" * 16 + b"nope\x00" + b"also-nope\x00"
    path = _elf64(tmp_path / "nongo.elf", e_type=2, phdrs=[(1, 6, load)])
    with pytest.raises(AnalysisError, match="malformed Go build info"):
        detect_go_buildinfo(path)


# ---- binmeta: cargo-auditable payload guards ----------------------------------


def _audit_elf(path: Path, note_name: bytes, desc: bytes) -> Path:
    """ELF64 carrying one ``AUDITABLE``-style note."""
    return _elf64(
        path,
        e_type=2,
        phdrs=[(4, 0, _note_blob(note_name, desc))],
    )


def test_cargo_auditable_empty_payload_raises(tmp_path: Path) -> None:
    """An empty audit-note descriptor is a typed error, not a summary."""
    path = _audit_elf(tmp_path / "empty_audit.elf", b"AUDITABLE\x00", b"")
    with pytest.raises(AnalysisError, match="empty cargo-auditable payload"):
        detect_cargo_auditable(path)


@pytest.mark.parametrize(
    "desc",
    [
        b'{"name": "crate"}',  # JSON object, not an array
        b"[42]",  # array entry that is not an object
        b'[{"version": "1.0"}]',  # entry without a name
    ],
)
def test_cargo_auditable_malformed_payloads_raise(tmp_path: Path, desc: bytes) -> None:
    """Malformed audit JSON payloads surface as typed errors."""
    path = _audit_elf(tmp_path / "bad_audit.elf", b"rust-audit\x00", desc)
    with pytest.raises(AnalysisError, match="cargo-auditable"):
        detect_cargo_auditable(path)


def test_cargo_audit_note_walk_breaks_on_bad_notes(tmp_path: Path) -> None:
    """Oversized and truncated audit notes end the walk without a payload."""
    good = _note_blob(b"GNU\x00", b"")  # not an audit owner: walk continues
    chopped = struct.pack("<III", 4, 999, 1) + b"\x00" * 8
    path = _elf64(tmp_path / "walk.elf", e_type=2, phdrs=[(4, 0, good + chopped)])
    assert detect_cargo_auditable(path) is None


# ---- binmeta: electron fuse wire guards ---------------------------------------


def test_fuse_wire_truncated_header_is_a_typed_error(tmp_path: Path) -> None:
    """A sentinel with fewer than two wire bytes is a typed error."""
    path = tmp_path / "stub.fuse"
    path.write_bytes(ELECTRON_FUSE_SENTINEL + b"\x01")
    with pytest.raises(AnalysisError, match="truncated Electron fuse wire"):
        detect_electron_fuses(path)


# ---- binmeta: kernel module (.modinfo) ----------------------------------------


def test_kernel_module_modinfo_degenerate_chunks(tmp_path: Path) -> None:
    """Chunks without '=' and empty keys are skipped; long values truncate."""
    modinfo = (
        b"vermagic=5.15.0-gentoo SMP mod_unload\0"
        b"no-equals-in-this-chunk\0"
        b"=value-without-key\0"
        b"license=GPL\0"
        b"long=" + b"v" * 250 + b"\0"
    )
    path = _elf64(
        tmp_path / "mod.ko", e_type=1, sections=[(".modinfo", 1, modinfo)]
    )
    info = detect_kernel_module(path)
    assert info is not None
    assert info.key_count == 3
    assert info.modinfo["vermagic"].startswith("5.15.0")
    assert info.modinfo["license"] == "GPL"
    assert info.modinfo["long"].endswith("...")
    assert len(info.modinfo["long"]) == 203
    assert info.evidence.source == "meta.modinfo"


def test_kernel_module_modinfo_without_pairs_returns_none(tmp_path: Path) -> None:
    """A ``.modinfo`` section holding no ``key=value`` pairs reports None."""
    path = _elf64(
        tmp_path / "bare.ko", e_type=1, sections=[(".modinfo", 1, b"justchunk\0")]
    )
    assert detect_kernel_module(path) is None


def test_kernel_module_bad_and_truncated_headers(tmp_path: Path) -> None:
    """Bad ELF identification and a cut header are typed errors."""
    bad_ident = tmp_path / "ident.ko"
    bad_ident.write_bytes(b"\x7fELF" + bytes([9, 1, 1, 0]) + bytes(8) + bytes(48))
    with pytest.raises(AnalysisError, match="malformed ELF identification"):
        detect_kernel_module(bad_ident)
    truncated = tmp_path / "cut.ko"
    truncated.write_bytes(b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + bytes(4))
    with pytest.raises(AnalysisError, match="truncated ELF header"):
        detect_kernel_module(truncated)


def test_kernel_module_without_section_table(tmp_path: Path) -> None:
    """An ET_REL image with no section header table reports None."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0
    )
    path = tmp_path / "nosect.ko"
    path.write_bytes(header + bytes(64))
    assert detect_kernel_module(path) is None


def test_kernel_module_short_section_table_breaks(tmp_path: Path) -> None:
    """A declared section count with no data behind it reports None."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 128, 0, 64, 56, 0, 64, 3, 0
    )
    path = tmp_path / "stubsh.ko"
    path.write_bytes(header)  # ends exactly where e_shoff points
    assert detect_kernel_module(path) is None


# ---- binmeta: desktop-app classification (PE CLR probes) -----------------------


def _pe_image(
    *,
    magic: int = 0x20B,
    rva_count: int = 16,
    clr_rva: int = 0,
    opt_size: int | None = None,
    sig: bytes = b"PE\x00\x00",
) -> bytes:
    """Synthetic PE: DOS header, COFF, optional header, one section."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt_len = 240 if opt_size is None else opt_size
    coff = struct.pack("<4sHHIIIHH", sig, 0x8664, 1, 0, 0, 0, opt_len, 0x0022)
    opt = bytearray(max(opt_len, 240))
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    dirs_off, entry = (112, 108) if magic == 0x20B else (96, 92)
    struct.pack_into("<I", opt, entry, rva_count)
    struct.pack_into("<I", opt, dirs_off + 14 * 8, clr_rva)
    sections = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00", 1, 0, 0x10, 0x200, 0x10, 0, 0, 0, 0
    )
    return bytes(dos) + coff + bytes(opt[:opt_len]) + sections


def test_desktop_app_dotnet_via_pe32_clr_directory(tmp_path: Path) -> None:
    """A PE32 image with a non-zero CLR data directory classifies as dotnet."""
    root = tmp_path / "DotNetApp"
    root.mkdir()
    (root / "app.exe").write_bytes(_pe_image(magic=0x10B, clr_rva=0x2000))
    info = detect_desktop_app(root)
    assert info is not None
    assert info.frameworks == ("dotnet",)


@pytest.mark.parametrize(
    "image_kwargs",
    [
        {"sig": b"NOPE"},  # PE signature missing
        {"opt_size": 1},  # optional header too short for a magic
        {"magic": 0x30B},  # unknown optional-header magic
        {"magic": 0x10B, "opt_size": 94},  # cut before the CLR directory entry
        {"rva_count": 14},  # data directory count too small for CLR (14)
    ],
)
def test_desktop_app_clr_probes_degrade_to_none(
    tmp_path: Path, image_kwargs: dict
) -> None:
    """Exes whose PE header cannot prove a CLR directory yield no dotnet."""
    root = tmp_path / "PlainApp"
    root.mkdir()
    (root / "app.exe").write_bytes(_pe_image(**image_kwargs))
    assert detect_desktop_app(root) is None


def test_desktop_app_unity_flag_and_walk_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk truncates at the file cap while Unity markers classify."""
    monkeypatch.setattr(binmeta, "MAX_DESKTOP_FILES", 2)
    root = tmp_path / "UnityGame"
    (root / "Game_Data").mkdir(parents=True)
    (root / "Game_Data" / "level0").write_bytes(b"assets")
    (root / "Game_Data" / "pad1.txt").write_bytes(b"pad")
    (root / "Game_Data" / "pad2.txt").write_bytes(b"pad")
    info = detect_desktop_app(root)
    assert info is not None
    assert "unity" in info.frameworks


def test_desktop_app_pe_probe_errors_are_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing PE probe is skipped; classification continues without it."""

    def _boom(path: Path) -> object:
        raise OSError("simulated open failure")

    monkeypatch.setattr(binmeta, "_open_file", _boom)
    root = tmp_path / "BrokenApp"
    root.mkdir()
    (root / "app.exe").write_bytes(_pe_image(clr_rva=0x2000))
    assert detect_desktop_app(root) is None


# ---- binmeta: APK signing block error matrix -----------------------------------


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _signer_record(sd: bytes) -> bytes:
    """One length-prefixed signer whose signed data is ``sd``."""
    return _u32(len(sd)) + sd


def _signed_data(digests: bytes, *, v3: bool = False, dg_len: int | None = None) -> bytes:
    """Signed data: length wrapper, digest list, cert/attr spans, v3 SDK tail."""
    rest = _u32(len(digests) if dg_len is None else dg_len) + digests + _u32(0) + _u32(0)
    if v3:
        rest += _u32(21) + _u32(33)
    return _u32(len(rest)) + rest


def _digest_record(alg: int = 1) -> bytes:
    return _u32(4) + _u32(alg)


def _v2_pair(value: bytes, pair_id: int = 0x7109871A) -> bytes:
    return _u64(4 + len(value)) + _u32(pair_id) + value


def _apk_block_bytes(pairs: bytes, *, declared: int | None = None,
                     trailer_size: int | None = None,
                     magic: bytes = APK_SIG_BLOCK_MAGIC) -> bytes:
    """A physically consistent signing block (declared defaults to true size)."""
    size = len(pairs) + 24 if declared is None else declared
    trailing = size if trailer_size is None else trailer_size
    return _u64(size) + pairs + _u64(trailing) + magic


def _apk_file(tmp_path: Path, block: bytes, *, chop: int = 0) -> Path:
    """Write zip stub + block + CD stub + EOCD (optionally chopped) to disk."""
    cd_offset = 30 + len(block)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0, 0, 16, cd_offset, 0)
    stub = b"PK\x03\x04" + b"\x00" * 26
    path = tmp_path / "signed.apk"
    path.write_bytes(stub + block + b"\x00" * 16 + eocd[: len(eocd) - chop])
    return path


def _plain_apk(
    tmp_path: Path,
    cd_offset: int,
    *,
    cd_size: int = 16,
    entries: int = 0,
    name: str = "bare.apk",
) -> Path:
    """A minimal EOCD (optionally lying) without a signing block."""
    path = tmp_path / name
    path.write_bytes(
        b"PK\x03\x04" + b"\x00" * 16
        + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, entries, entries,
                      cd_size, cd_offset, 0)
    )
    return path


def _signer_seq(sd: bytes) -> bytes:
    """Length-prefixed signer sequence holding exactly one signer."""
    rec = _signer_record(sd)
    return _u32(len(rec)) + rec


def test_apk_signer_sequence_length_lies(tmp_path: Path) -> None:
    """A declared signer sequence longer than the value is a typed error."""
    sd = _signed_data(_digest_record(1))
    value = _u32(9999) + _signer_record(sd)
    path = _apk_file(tmp_path, _apk_block_bytes(_v2_pair(value)))
    with pytest.raises(AnalysisError, match="malformed APK signer sequence"):
        detect_apk_signing(path)


def test_apk_signer_record_too_short(tmp_path: Path) -> None:
    """A signer length below the minimum is a typed error."""
    sd = _signed_data(_digest_record(1))
    value = _u32(len(sd) + 4) + _u32(0) + sd  # slen = 0
    path = _apk_file(tmp_path, _apk_block_bytes(_v2_pair(value)))
    with pytest.raises(AnalysisError, match="truncated APK signer record"):
        detect_apk_signing(path)


def test_apk_too_many_signers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Signers beyond the budget are refused."""
    monkeypatch.setattr(binmeta, "MAX_APK_SIGNERS", 1)
    sd = _signed_data(_digest_record(1))
    seq = _signer_record(sd) + _signer_record(sd)
    value = _u32(len(seq)) + seq
    path = _apk_file(tmp_path, _apk_block_bytes(_v2_pair(value)))
    with pytest.raises(AnalysisError, match="more than 1 APK signers"):
        detect_apk_signing(path)


def test_apk_truncated_digest_record(tmp_path: Path) -> None:
    """A digest record length that overruns its list is a typed error."""
    digests = _digest_record(1) + _u32(8)  # next record announces, never lands
    value = _v2_pair(_signer_seq(_signed_data(digests)))
    path = _apk_file(tmp_path, _apk_block_bytes(value))
    with pytest.raises(AnalysisError, match="truncated APK digest record"):
        detect_apk_signing(path)


def test_apk_truncated_signed_data(tmp_path: Path) -> None:
    """A signed-data length that overruns the signer is a typed error."""
    sd = _signed_data(_digest_record(1))
    bad = _u32(len(sd) + 100) + sd
    value = _v2_pair(_signer_seq(bad))
    path = _apk_file(tmp_path, _apk_block_bytes(value))
    with pytest.raises(AnalysisError, match="truncated APK signed-data"):
        detect_apk_signing(path)


def test_apk_truncated_digest_list(tmp_path: Path) -> None:
    """A digest-list length that overruns the signed data is a typed error."""
    sd = _signed_data(_digest_record(1), dg_len=999)
    value = _v2_pair(_signer_seq(sd))
    path = _apk_file(tmp_path, _apk_block_bytes(value))
    with pytest.raises(AnalysisError, match="truncated APK digest list"):
        detect_apk_signing(path)


def test_apk_v3_missing_sdk_fields(tmp_path: Path) -> None:
    """A v3 signed-data block without the min/max SDK tail is a typed error."""
    value = _v2_pair(_signer_seq(_signed_data(_digest_record(1))), 0xF05368C0)
    path = _apk_file(tmp_path, _apk_block_bytes(value))
    with pytest.raises(AnalysisError, match="min/max SDK"):
        detect_apk_signing(path)


def test_apk_block_declared_size_under_minimum(tmp_path: Path) -> None:
    """A declared size under 24 bytes is a typed error."""
    block = _u64(8) + b"\x00" * 8 + _u64(8) + APK_SIG_BLOCK_MAGIC
    path = _apk_file(tmp_path, block)
    with pytest.raises(AnalysisError, match="size < 24"):
        detect_apk_signing(path)


def test_apk_block_declared_size_overreach(tmp_path: Path) -> None:
    """A declared block reaching before the zip start is a typed error."""
    pairs = _v2_pair(_signer_seq(_signed_data(_digest_record(1))))
    declared = len(pairs) + 240
    block = _u64(declared) + pairs + _u64(declared) + APK_SIG_BLOCK_MAGIC
    path = _apk_file(tmp_path, block)
    with pytest.raises(AnalysisError, match="before zip start"):
        detect_apk_signing(path)


def test_apk_block_leading_size_mismatch(tmp_path: Path) -> None:
    """Leading size field disagreeing with the footer is a typed error."""
    pairs = _v2_pair(_signer_seq(_signed_data(_digest_record(1))))
    size = len(pairs) + 24
    block = _u64(size + 3) + pairs + _u64(size) + APK_SIG_BLOCK_MAGIC
    path = _apk_file(tmp_path, block)
    with pytest.raises(AnalysisError, match="size field mismatch"):
        detect_apk_signing(path)


def test_apk_block_malformed_pair_length(tmp_path: Path) -> None:
    """A pair length that overruns the block is a typed error."""
    pairs = _u64(9999) + _u32(0x7109871A) + b"\x00" * 4
    path = _apk_file(tmp_path, _apk_block_bytes(pairs))
    with pytest.raises(AnalysisError, match="malformed APK Signing Block pair"):
        detect_apk_signing(path)


def test_apk_too_many_pairs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pairs beyond the budget are refused."""
    monkeypatch.setattr(binmeta, "MAX_APK_PAIRS", 1)
    sd = _signed_data(_digest_record(1))
    sd_v3 = _signed_data(_digest_record(1), v3=True)
    pairs = _v2_pair(_signer_seq(sd)) + _v2_pair(_signer_seq(sd_v3), 0x1B93AD61)
    path = _apk_file(tmp_path, _apk_block_bytes(pairs))
    with pytest.raises(AnalysisError, match="more than 1 signing-block pairs"):
        detect_apk_signing(path)


def test_apk_eocd_short_tail(tmp_path: Path) -> None:
    """An EOCD record cut below 22 bytes is a typed error."""
    path = tmp_path / "chopped.apk"
    path.write_bytes(b"PK\x03\x04junk\x00\x00\x00PK\x05\x06" + b"\x00" * 8)
    with pytest.raises(AnalysisError, match="End Of Central Directory"):
        detect_apk_signing(path)


def test_apk_zip64_rejected(tmp_path: Path) -> None:
    """A zip64 central-directory offset is refused with a typed message."""
    path = _plain_apk(tmp_path, 0xFFFFFFFF)
    with pytest.raises(AnalysisError, match="zip64"):
        detect_apk_signing(path)


def test_apk_eocd_offset_outside_file(tmp_path: Path) -> None:
    """A central-directory offset past EOF is a typed error."""
    path = _plain_apk(tmp_path, 9_999_999)
    with pytest.raises(AnalysisError, match="points outside the file"):
        detect_apk_signing(path)


def test_apk_corrupt_zip_surfaces_as_typed_error(tmp_path: Path) -> None:
    """An EOCD whose central directory is garbage becomes a typed error."""
    path = _plain_apk(tmp_path, 2, entries=1)
    with pytest.raises(AnalysisError, match="malformed zip archive"):
        detect_apk_signing(path)


def test_apk_plain_zip_without_signing_returns_none(tmp_path: Path) -> None:
    """A valid zip with no signing block and no v1 manifest reports None."""
    import zipfile

    path = tmp_path / "plain.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("assets/data.txt", "payload")
    assert detect_apk_signing(path) is None







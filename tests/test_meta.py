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




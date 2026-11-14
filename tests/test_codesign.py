"""Mach-O code-signature lite tests (lane-format2).

All fixtures are hand-built Mach-O + SuperBlob bytes assembled in-test;
nothing touches the network, the filesystem beyond ``tmp_path``, or real
signed binaries. Parse-only: the suite never asserts anything about trust.
"""

from __future__ import annotations

import asyncio
import json
import plistlib
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codevanta.analysis.codesign import (
    MAX_ENTITLEMENT_KEYS,
    MAX_SLOTS,
    inspect_codesign,
)
from codevanta.cli.main import app
from codevanta.core.report import AnalysisError
from codevanta.mcp_server import tools
from codevanta.mcp_server.server import build_server

runner = CliRunner()


# ---- fixture builders ----------------------------------------------------------


def _der(tag: int, content: bytes) -> bytes:
    """One DER TLV (short- or long-form length as the content requires)."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def _xml_plist(keys: list[tuple[str, str]]) -> bytes:
    """A minimal Apple XML plist with one string value per key."""
    body = "".join(f"<key>{key}</key><string>{value}</string>" for key, value in keys)
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<plist version="1.0"><dict>'
        + body.encode("utf-8")
        + b"</dict></plist>\n"
    )


def _entitlements_blob(payload: bytes) -> bytes:
    """Double DER-wrapped entitlements blob (outer A7 -> OCTET STRING -> A7)."""
    inner = _der(0xA7, _der(0x04, payload))
    outer = _der(0xA7, _der(0x04, inner))
    return struct.pack(">II", 0xFADE7171, 8 + len(outer)) + outer


def _code_directory(identifier: bytes = b"com.example.app\x00") -> bytes:
    """A hand-built v0x20400 CodeDirectory with one code slot.

    Header: magic, length, version, flags, hashOffset, identOffset,
    nSpecialSlots, nCodeSlots (8x u32), execSegBase/Limit/Flags (3x u64) --
    56 bytes -- then the identifier string and the hash slot.
    """
    hashdata = b"\x01" * 32
    body_length = 56 + len(identifier) + len(hashdata)
    return (
        struct.pack(
            ">IIIIIII",
            0xFADE0C02,
            body_length,
            0x20400,
            0,
            56 + len(identifier),
            56,
            0,
        )
        + struct.pack(">I", 1)
        + struct.pack(">QQQ", 0, 0, 0)
        + identifier
        + hashdata
    )


def _cms_blob(certs: int = 2) -> bytes:
    """A minimal CMS ContentInfo whose SignedData carries *certs* certificates.

    Layout per PKCS#7/CMS: ``SignedData ::= version, [0] digestAlgorithms,
    [0] certificates, ...`` -- the certificate set is the second context tag
    inside SignedData.
    """
    cert = _der(0x30, b"\x02\x01\x01")
    signed_data = _der(0x30, b"\x02\x01\x00" + _der(0xA0, cert * certs))
    oid = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
    return _der(0x30, _der(0x06, oid) + _der(0xA0, signed_data))


def _superblob(blobs: list[tuple[int, bytes]]) -> bytes:
    """Index + payload for ``(slot type, blob)`` pairs."""
    offset = 12 + len(blobs) * 8
    laid: list[tuple[int, int, int]] = []
    cursor = offset
    for slot_type, blob in blobs:
        laid.append((slot_type, cursor, len(blob)))
        cursor += len(blob)
    index = b"".join(struct.pack(">II", slot, off) for slot, off, _ in laid)
    payload = b"".join(blob for _, blob in blobs)
    return struct.pack(">III", 0xFADE0CC0, cursor, len(blobs)) + index + payload


def _macho(
    path: Path,
    signature: bytes | None,
    *,
    byteorder: str = "<",
    lc_offset: int = 32,
) -> Path:
    """A 64-bit Mach-O with one LC_CODE_SIGNATURE pointing at ``signature``.

    ``byteorder=">"`` builds a byte-swapped (MH_CIGAM) thin binary: the
    header, load command and all multi-byte Mach-O fields are big-endian.
    """
    ncmds = 1 if signature is not None else 0
    header = struct.pack(f"{byteorder}IIIIIIII", 0xFEEDFACF, 7, 3, 2, ncmds, 64, 0, 0)
    out = bytearray(header)
    if signature is not None:
        out += struct.pack(f"{byteorder}IIII", 0x1D, 16, lc_offset + 64, len(signature))
    payload_at = lc_offset + 64
    out += b"\x00" * (payload_at - len(out))
    if signature is not None:
        out += signature
    path.write_bytes(bytes(out))
    return path


def _signed_macho(tmp_path: Path, name: str = "app.macho") -> Path:
    """The happy-path fixture: code directory + entitlements + CMS."""
    entitlements = _entitlements_blob(
        _xml_plist(
            [
                ("com.apple.developer.team-identifier", "TEAM99"),
                ("com.apple.security.network.client", "allowed"),
            ]
        )
    )
    signature = _superblob(
        [
            (0, _code_directory()),
            (7, entitlements),
            (0x10000, _cms_blob(2)),
        ]
    )
    return _macho(tmp_path / name, signature)


# ---- happy path ------------------------------------------------------------------


class TestHappyPath:
    def test_full_signature(self, tmp_path: Path) -> None:
        path = _signed_macho(tmp_path)
        report = inspect_codesign(path)
        assert report is not None
        assert report.macho_kind == "macho64"
        assert report.endian == "little"
        assert report.identifier == "com.example.app"
        assert report.team_id == "TEAM99"
        assert report.certificates_count == 2
        assert report.entitlements_keys == (
            "com.apple.developer.team-identifier",
            "com.apple.security.network.client",
        )
        assert report.slot_count == 3
        assert [name for _, name, _, _ in report.slots] == [
            "code-directory",
            "entitlements",
            "cms-signature",
        ]
        assert not report.slots_truncated
        assert not report.entitlements_truncated
        assert report.warnings == []
        assert report.evidence.source == "codesign.macho"
        assert report.evidence.confidence.value == "high"
        assert report.signature_offset == 96

    def test_to_dict_is_json_safe(self, tmp_path: Path) -> None:
        report = inspect_codesign(_signed_macho(tmp_path))
        assert report is not None
        payload = report.to_dict()
        assert json.dumps(payload)
        assert payload["evidence"]["source"] == "codesign.macho"

    def test_entitlements_at_xnu_slot_five(self, tmp_path: Path) -> None:
        """The xnu slot numbering (5) is honoured too; the blob magic decides."""
        entitlements = _entitlements_blob(
            _xml_plist([("com.apple.security.network.client", "allowed")])
        )
        signature = _superblob([(0, _code_directory()), (5, entitlements)])
        report = inspect_codesign(_macho(tmp_path / "xnu.macho", signature))
        assert report is not None
        assert report.entitlements_keys == ("com.apple.security.network.client",)
        assert report.team_id is None

    def test_big_endian_macho(self, tmp_path: Path) -> None:
        """A byte-swapped (MH_CIGAM) thin binary parses big-endian."""
        entitlements = _entitlements_blob(_xml_plist([("k", "v")]))
        signature = _superblob([(0, _code_directory()), (7, entitlements)])
        path = _macho(tmp_path / "be.macho", signature, byteorder=">")
        report = inspect_codesign(path)
        assert report is not None
        assert report.endian == "big"

    def test_unsigned_macho_is_none(self, tmp_path: Path) -> None:
        path = _macho(tmp_path / "clean.macho", None)
        assert inspect_codesign(path) is None

    def test_non_macho_is_none(self, tmp_path: Path) -> None:
        p = tmp_path / "junk.bin"
        p.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
        assert inspect_codesign(p) is None

    def test_short_file_is_none(self, tmp_path: Path) -> None:
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"\xcf\xfa\xed\xfe")
        assert inspect_codesign(p) is None

    def test_bplist_entitlements(self, tmp_path: Path) -> None:
        payload = plistlib.dumps({"com.apple.security.app-sandbox": True})
        entitlements = _entitlements_blob(payload)
        signature = _superblob([(0, _code_directory()), (7, entitlements)])
        report = inspect_codesign(_macho(tmp_path / "bplist.macho", signature))
        assert report is not None
        assert report.entitlements_keys == ("com.apple.security.app-sandbox",)

    def test_no_cms_slot(self, tmp_path: Path) -> None:
        signature = _superblob([(0, _code_directory())])
        report = inspect_codesign(_macho(tmp_path / "nocms.macho", signature))
        assert report is not None
        assert report.certificates_count is None
        assert report.identifier == "com.example.app"

    def test_undecodable_cms_warns(self, tmp_path: Path) -> None:
        signature = _superblob([(0, _code_directory()), (0x10000, b"\x30\x02\x01\x00")])
        report = inspect_codesign(_macho(tmp_path / "badcms.macho", signature))
        assert report is not None
        assert report.certificates_count is None
        assert any("CMS" in warning for warning in report.warnings)


# ---- bounds ------------------------------------------------------------------------


class TestBounds:
    def test_entitlement_keys_bounded(self, tmp_path: Path) -> None:
        keys = [
            (f"com.example.key.{index:03d}", "v")
            for index in range(MAX_ENTITLEMENT_KEYS + 8)
        ]
        entitlements = _entitlements_blob(_xml_plist(keys))
        signature = _superblob([(0, _code_directory()), (7, entitlements)])
        report = inspect_codesign(_macho(tmp_path / "many.macho", signature))
        assert report is not None
        assert len(report.entitlements_keys) == MAX_ENTITLEMENT_KEYS
        assert report.entitlements_truncated
        assert any("key limit" in warning for warning in report.warnings)


# ---- typed errors --------------------------------------------------------------------


class TestMalformed:
    def test_fat_binary_is_refused(self, tmp_path: Path) -> None:
        p = tmp_path / "fat.macho"
        p.write_bytes(struct.pack("<IIIIIIII", 0xCAFEBABE, *([0] * 7)))
        with pytest.raises(AnalysisError, match="fat"):
            inspect_codesign(p)

    def test_oversized_signature_offset(self, tmp_path: Path) -> None:
        signature = _superblob([(0, _code_directory())])
        p = tmp_path / "over.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 1, 64, 0, 0)
        lc = struct.pack("<IIII", 0x1D, 16, 96, len(signature) * 40)
        p.write_bytes(header + lc + b"\x00" * 64 + signature)
        with pytest.raises(AnalysisError, match="does not fit"):
            inspect_codesign(p)

    def test_malformed_load_command_size(self, tmp_path: Path) -> None:
        p = tmp_path / "badlc.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 1, 64, 0, 0)
        lc = struct.pack("<IIII", 0x1D, 4, 96, 16)
        p.write_bytes(header + lc + b"\x00" * 64)
        with pytest.raises(AnalysisError, match="malformed load command"):
            inspect_codesign(p)

    def test_truncated_load_command_table(self, tmp_path: Path) -> None:
        """``ncmds`` promises more commands than the file can hold."""
        p = tmp_path / "trunc.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 2, 64, 0, 0)
        filler = struct.pack("<IIII", 0x19, 16, 0, 0)  # LC_SOURCE_VERSION, cmdsize 16
        p.write_bytes(header + filler)
        with pytest.raises(AnalysisError, match="truncated"):
            inspect_codesign(p)

    def test_bad_superblob_magic(self, tmp_path: Path) -> None:
        signature = struct.pack(">III", 0xDEADBEF0, 24, 1) + b"\x00" * 24
        with pytest.raises(AnalysisError, match="SuperBlob"):
            inspect_codesign(_macho(tmp_path / "badmagic.macho", signature))

    def test_slot_offset_past_blob(self, tmp_path: Path) -> None:
        signature = (
            struct.pack(">III", 0xFADE0CC0, 12 + 8, 1)
            + struct.pack(">II", 0, 9999)
            + b"\x00" * 32
        )
        with pytest.raises(AnalysisError, match="points past the blob"):
            inspect_codesign(_macho(tmp_path / "badslot.macho", signature))

    def test_slot_overruns_superblob(self, tmp_path: Path) -> None:
        cd = _code_directory()
        signature = (
            struct.pack(">III", 0xFADE0CC0, 12 + 8, 1)
            + struct.pack(">II", 0, 20)
            + struct.pack(">II", 0xFADE0C02, 10_000)
            + b"\x00" * 8
            + cd
        )
        with pytest.raises(AnalysisError, match="overrunning the SuperBlob"):
            inspect_codesign(_macho(tmp_path / "bigslot.macho", signature))

    def test_code_directory_without_identifier(self, tmp_path: Path) -> None:
        cd = _code_directory(identifier=b"\x00\x00")
        signature = _superblob([(0, cd)])
        with pytest.raises(AnalysisError, match="identifier"):
            inspect_codesign(_macho(tmp_path / "noid.macho", signature))

    def test_entitlements_without_plist(self, tmp_path: Path) -> None:
        blob = struct.pack(">II", 0xFADE7171, 16) + b"\x00" * 8
        signature = _superblob([(0, _code_directory()), (7, blob)])
        with pytest.raises(AnalysisError, match="plist"):
            inspect_codesign(_macho(tmp_path / "noent.macho", signature))

    def test_undecodable_plist(self, tmp_path: Path) -> None:
        blob = struct.pack(">II", 0xFADE7171, 8 + 8) + b"<plist" + b"\x00" * 2
        signature = _superblob([(0, _code_directory()), (7, blob)])
        with pytest.raises(AnalysisError, match="undecodable"):
            inspect_codesign(_macho(tmp_path / "badplist.macho", signature))

    def test_empty_file_is_typed(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        with pytest.raises(AnalysisError, match="empty"):
            inspect_codesign(p)


# ---- CLI + MCP ------------------------------------------------------------------------


def test_cli_codesign_table(tmp_path: Path) -> None:
    path = _signed_macho(tmp_path)
    result = runner.invoke(app, ["codesign", str(path)])
    assert result.exit_code == 0, result.stdout
    assert "com.example.app" in result.stdout
    assert "TEAM99" in result.stdout
    assert "evidence: codesign.macho" in result.stdout


def test_cli_codesign_json(tmp_path: Path) -> None:
    path = _signed_macho(tmp_path)
    result = runner.invoke(app, ["codesign", str(path), "--json"])
    assert result.exit_code == 0, result.stdout
    assert '"certificates_count": 2' in result.stdout


def test_cli_codesign_unsigned_exits_two(tmp_path: Path) -> None:
    path = _macho(tmp_path / "plain.macho", None)
    result = runner.invoke(app, ["codesign", str(path)])
    assert result.exit_code == 2


def test_cli_codesign_garbage_exits_two(tmp_path: Path) -> None:
    p = tmp_path / "garbage.bin"
    p.write_bytes(b"\xde\xad\xbe\xef" * 32)
    result = runner.invoke(app, ["codesign", str(p)])
    assert result.exit_code == 2


def test_mcp_tools_codesign(tmp_path: Path) -> None:
    path = _signed_macho(tmp_path)
    payload = tools.codevanta_codesign(str(path))
    assert payload["identifier"] == "com.example.app"
    assert payload["team_id"] == "TEAM99"
    assert payload["evidence"]["source"] == "codesign.macho"


def test_mcp_tools_codesign_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        tools.codevanta_codesign(str(tmp_path / "missing.macho"))


def test_mcp_tools_codesign_unsigned_is_typed(tmp_path: Path) -> None:
    path = _macho(tmp_path / "unsigned.macho", None)
    with pytest.raises(AnalysisError, match="no embedded code signature"):
        tools.codevanta_codesign(str(path))


def test_mcp_server_lists_and_calls_codesign(tmp_path: Path) -> None:
    listed = asyncio.run(build_server().list_tools())
    assert "codevanta_codesign" in [tool.name for tool in listed]
    path = _signed_macho(tmp_path)
    result = asyncio.run(
        build_server().call_tool("codevanta_codesign", {"path": str(path)})
    )
    structured = getattr(result, "structuredContent", None)
    if structured:
        payload = structured
    else:
        payload = json.loads(result.content[0].text)
    assert payload["identifier"] == "com.example.app"


# ---- coverage batch: guard rails and DER variants ---------------------------------


class TestCoverageGuards:
    """Typed-error and DER-variant paths the happy path never touches."""

    def test_directory_is_none(self, tmp_path: Path) -> None:
        assert inspect_codesign(tmp_path) is None

    def test_missing_file_is_typed(self, tmp_path: Path) -> None:
        with pytest.raises(AnalysisError, match="cannot stat"):
            inspect_codesign(tmp_path / "ghost.macho")

    def test_truncated_macho_header(self, tmp_path: Path) -> None:
        """A 64-bit binary cut between the 28-byte minimum and the 32-byte header."""
        p = tmp_path / "shorthead.macho"
        p.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 26)
        with pytest.raises(AnalysisError, match="truncated Mach-O header"):
            inspect_codesign(p)

    def test_macho32_happy_path(self, tmp_path: Path) -> None:
        """A 28-byte-header (32-bit) thin binary parses the same way."""
        signature = _superblob([(0, _code_directory())])
        header = struct.pack("<IIIIIII", 0xFEEDFACE, 7, 3, 2, 1, 64, 0)
        lc = struct.pack("<IIII", 0x1D, 16, 28 + 64, len(signature))
        out = bytearray(header + lc)
        out += b"\x00" * (28 + 64 - len(out))
        out += signature
        path = tmp_path / "m32.macho"
        path.write_bytes(bytes(out))
        report = inspect_codesign(path)
        assert report is not None
        assert report.macho_kind == "macho32"
        assert report.identifier == "com.example.app"

    def test_load_command_table_ends_mid_command(self, tmp_path: Path) -> None:
        p = tmp_path / "mid.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 2, 64, 0, 0)
        p.write_bytes(header + b"\x00" * 4)
        with pytest.raises(AnalysisError, match="truncated"):
            inspect_codesign(p)

    def test_signature_command_too_small(self, tmp_path: Path) -> None:
        p = tmp_path / "lc8.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 1, 64, 0, 0)
        lc = struct.pack("<II", 0x1D, 8)  # no dataoff/datasize payload
        p.write_bytes(header + lc + b"\x00" * 64)
        with pytest.raises(AnalysisError, match="too small to carry dataoff"):
            inspect_codesign(p)

    def test_too_many_load_commands(self, tmp_path: Path) -> None:
        """520 tiny load commands exhaust the lane's 512-command walk budget."""
        p = tmp_path / "many-lc.macho"
        header = struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 3, 2, 520, 520 * 8, 0, 0)
        filler = struct.pack("<II", 0x19, 8) * 520
        p.write_bytes(header + filler)
        with pytest.raises(AnalysisError, match="520 load commands"):
            inspect_codesign(p)

    def test_superblob_too_small(self, tmp_path: Path) -> None:
        signature = b"\xfa\xde\x0c\xc0\x00\x00\x00\x08"
        with pytest.raises(AnalysisError, match="too small for a SuperBlob"):
            inspect_codesign(_macho(tmp_path / "small-sig.macho", signature))

    def test_superblob_length_mismatch(self, tmp_path: Path) -> None:
        signature = struct.pack(">III", 0xFADE0CC0, 0, 1) + b"\x00" * 40
        with pytest.raises(AnalysisError, match="does not fit"):
            inspect_codesign(_macho(tmp_path / "badlen.macho", signature))

    def test_slot_cap_truncates(self, tmp_path: Path) -> None:
        cd = _code_directory()
        count = MAX_SLOTS + 1
        blob_offset = 12 + count * 8
        index = b"".join(
            struct.pack(">II", 0x4000 + slot, blob_offset) for slot in range(count)
        )
        signature = (
            struct.pack(">III", 0xFADE0CC0, blob_offset + len(cd), count) + index + cd
        )
        report = inspect_codesign(_macho(tmp_path / "capslots.macho", signature))
        assert report is not None
        assert report.slots_truncated
        assert len(report.slots) == MAX_SLOTS
        assert any("slot limit" in warning for warning in report.warnings)

    def test_cms_slot_truncated_der(self, tmp_path: Path) -> None:
        signature = _superblob([(0x10000, b"\x30")])
        with pytest.raises(AnalysisError, match="truncated DER"):
            inspect_codesign(_macho(tmp_path / "der-trunc.macho", signature))

    def test_blob_header_below_minimum(self, tmp_path: Path) -> None:
        signature = (
            struct.pack(">III", 0xFADE0CC0, 12 + 8, 1)
            + struct.pack(">II", 0x2, 20)
            + struct.pack(">II", 0xFADE0B01, 4)
            + b"\x00" * 16
        )
        with pytest.raises(AnalysisError, match="below the 8-byte blob header"):
            inspect_codesign(_macho(tmp_path / "shortblob.macho", signature))

    def test_code_directory_header_too_small(self, tmp_path: Path) -> None:
        cd = struct.pack(">II", 0xFADE0C02, 8)
        signature = _superblob([(0, cd)])
        with pytest.raises(AnalysisError, match="too small for a CodeDirectory"):
            inspect_codesign(_macho(tmp_path / "cd8.macho", signature))

    def test_identifier_offset_out_of_range(self, tmp_path: Path) -> None:
        cd = (
            struct.pack(">IIIIIII", 0xFADE0C02, 56, 0x20400, 0, 56, 4096, 0)
            + struct.pack(">I", 1)
            + struct.pack(">QQQ", 0, 0, 0)
            + b"\x00" * 32
        )
        signature = _superblob([(0, cd)])
        with pytest.raises(AnalysisError, match="no identifier string"):
            inspect_codesign(_macho(tmp_path / "badoff.macho", signature))

    def test_plist_decodes_to_non_dict(self, tmp_path: Path) -> None:
        payload = plistlib.dumps(["not", "a", "dict"])
        entitlements = _entitlements_blob(payload)
        signature = _superblob([(0, _code_directory()), (7, entitlements)])
        with pytest.raises(AnalysisError, match="expected a dict"):
            inspect_codesign(_macho(tmp_path / "list-plist.macho", signature))

    def test_cms_not_a_sequence(self, tmp_path: Path) -> None:
        signature = _superblob([(0, _code_directory()), (0x10000, b"\x31\x02\x01\x00")])
        report = inspect_codesign(_macho(tmp_path / "setfirst.macho", signature))
        assert report is not None
        assert report.certificates_count is None

    def test_cms_signed_data_not_a_sequence(self, tmp_path: Path) -> None:
        oid = bytes.fromhex("2a864886f70d010702")
        blob = _der(0x30, _der(0x06, oid) + _der(0xA0, b"\x02\x01\x00"))
        signature = _superblob([(0, _code_directory()), (0x10000, blob)])
        report = inspect_codesign(_macho(tmp_path / "intsd.macho", signature))
        assert report is not None
        assert report.certificates_count is None

    def test_cms_without_certificates(self, tmp_path: Path) -> None:
        oid = bytes.fromhex("2a864886f70d010702")
        blob = _der(0x30, _der(0x06, oid) + _der(0xA0, _der(0x30, b"\x02\x01\x00")))
        signature = _superblob([(0, _code_directory()), (0x10000, blob)])
        report = inspect_codesign(_macho(tmp_path / "nocerts.macho", signature))
        assert report is not None
        assert report.certificates_count is None

    def test_cms_digest_algorithms_then_certificates(self, tmp_path: Path) -> None:
        """The standard two-[0] layout: digestAlgorithms first, certificates second."""
        cert = _der(0x30, b"\x02\x01\x01")
        signed = _der(
            0x30,
            b"\x02\x01\x00"
            + _der(0xA0, _der(0x31, b"\x06\x01\x2a"))  # digestAlgorithms
            + _der(0xA0, cert * 3),  # certificates, IMPLICIT SET
        )
        oid = bytes.fromhex("2a864886f70d010702")
        blob = _der(0x30, _der(0x06, oid) + _der(0xA0, signed))
        signature = _superblob([(0, _code_directory()), (0x10000, blob)])
        report = inspect_codesign(_macho(tmp_path / "two-a0.macho", signature))
        assert report is not None
        assert report.certificates_count == 3

    def test_cms_explicit_certificate_set(self, tmp_path: Path) -> None:
        """Explicit-form certificates: [0] wraps an inner SET OF Certificate."""
        cert = _der(0x30, b"\x02\x01\x01")
        signed = _der(0x30, b"\x02\x01\x00" + _der(0xA0, _der(0x31, cert * 2)))
        oid = bytes.fromhex("2a864886f70d010702")
        blob = _der(0x30, _der(0x06, oid) + _der(0xA0, signed))
        signature = _superblob([(0, _code_directory()), (0x10000, blob)])
        report = inspect_codesign(_macho(tmp_path / "explicit.macho", signature))
        assert report is not None
        assert report.certificates_count == 2

    def test_cms_certificate_set_ends_mid_tlv(self, tmp_path: Path) -> None:
        cert = _der(0x30, b"\x02\x01\x01")
        signed = _der(0x30, b"\x02\x01\x00" + _der(0xA0, cert + b"\x02\x05\x99"))
        oid = bytes.fromhex("2a864886f70d010702")
        blob = _der(0x30, _der(0x06, oid) + _der(0xA0, signed))
        signature = _superblob([(0, _code_directory()), (0x10000, blob)])
        report = inspect_codesign(_macho(tmp_path / "midtlv.macho", signature))
        assert report is not None
        assert report.certificates_count == 1
        assert any("mid-TLV" in warning for warning in report.warnings)

    def test_cms_long_form_lengths_and_cap(self, tmp_path: Path) -> None:
        """A CMS over 127 bytes exercises DER long-form lengths and the 16-cert cap."""
        signature = _superblob([(0, _code_directory()), (0x10000, _cms_blob(60))])
        report = inspect_codesign(_macho(tmp_path / "longder.macho", signature))
        assert report is not None
        assert report.certificates_count is not None
        assert report.certificates_count <= 16
        assert any("certificate limit" in warning for warning in report.warnings)

    def test_second_entitlements_slot_is_ignored(self, tmp_path: Path) -> None:
        ent1 = _entitlements_blob(_xml_plist([("first.key", "1")]))
        ent2 = _entitlements_blob(_xml_plist([("second.key", "2")]))
        signature = _superblob([(0, _code_directory()), (7, ent1), (7, ent2)])
        report = inspect_codesign(_macho(tmp_path / "two-ent.macho", signature))
        assert report is not None
        assert report.entitlements_keys == ("first.key",)

    def test_second_cms_slot_is_ignored(self, tmp_path: Path) -> None:
        identification = struct.pack(">II", 0xFADE0B01, 8)
        signature = _superblob(
            [
                (0, _code_directory()),
                (0x10000, _cms_blob(2)),
                (0x10001, identification),
            ]
        )
        report = inspect_codesign(_macho(tmp_path / "two-cms.macho", signature))
        assert report is not None
        assert report.certificates_count == 2

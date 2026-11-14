"""Pure-Python PE certificate table tests (hand-built DER, fully offline).

The SignedData blob is hand-encoded with tiny DER helpers (no crypto
library, no external tool) exactly per the mission recipe::

    SEQUENCE{ version, digestAlgorithms, contentInfo,
              signerInfo{ version, sid, digestAlgorithm,
                          signedAttrs{signingTime UTCTime},
                          signatureAlgorithm, signature OCTET STRING } }

and is parsed back field by field. Malformed-DER cases prove the typed
AnalysisError; the PE wrapper cases build a minimal PE32+/PE32 image whose
security data directory points at the appended certificate table.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codevanta.analysis import pe_certs
from codevanta.analysis.pe_certs import (
    MAX_CERT_ENTRIES,
    MAX_SIGNERS,
    inspect_cert_table,
    parse_certificate_table,
    parse_pkcs7_signed_data,
)
from codevanta.core.report import AnalysisError

# ---- tiny DER encoder (test-only) ----------------------------------------------


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def _seq(*children: bytes) -> bytes:
    return _tlv(0x30, b"".join(children))


def _setof(*children: bytes) -> bytes:
    return _tlv(0x31, b"".join(children))


def _ctx(index: int, content: bytes, *, constructed: bool = True) -> bytes:
    tag = 0x80 | index | (0x20 if constructed else 0x00)
    return _tlv(tag, content)


def _oid(dotted: str) -> bytes:
    parts = [int(piece) for piece in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = part
        stack: list[int] = []
        while True:
            stack.append(chunk & 0x7F)
            chunk >>= 7
            if chunk == 0:
                break
        for position, byte in enumerate(reversed(stack)):
            if position != len(stack) - 1:
                body.append(byte | 0x80)
            else:
                body.append(byte)
    return _tlv(0x06, bytes(body))


def _int(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _octet(content: bytes) -> bytes:
    return _tlv(0x04, content)


def _utctime(text: str) -> bytes:
    return _tlv(0x17, text.encode("ascii"))


def _gtime(text: str) -> bytes:
    return _tlv(0x18, text.encode("ascii"))


# ---- fixture builders -----------------------------------------------------------


def build_signed_data_blob(
    *,
    signer_count: int = 1,
    with_signed_attrs: bool = True,
    utctime_text: str = "230517123000Z",
    digest_oid: str = "2.16.840.1.101.3.4.2.1",
    signature_oid: str = "1.2.840.113549.1.1.11",
    serial: int = 0x0123456789ABCDEF,
) -> bytes:
    """Hand-encode the mission's minimal PKCS#7 SignedData structure."""
    signers: list[bytes] = []
    for index in range(signer_count):
        fields: list[bytes] = [
            _int(1),  # version
            _seq(_seq(_oid("2.5.4.3")), _int(serial + index)),  # sid
            _seq(_oid(digest_oid)),  # digestAlgorithm
        ]
        if with_signed_attrs:
            attrs = _ctx(
                0,
                _seq(_oid("1.2.840.113549.1.9.5"), _setof(_utctime(utctime_text))),
            )
            fields.append(attrs)
        fields.append(_seq(_oid(signature_oid)))  # signatureAlgorithm
        fields.append(_octet(bytes(range(32))))  # signature
        signers.append(_seq(*fields))
    signer_infos = _setof(*signers)
    signed_data = _seq(_int(1), _setof(_seq(_oid(digest_oid))), _seq(_oid("1.2.840.113549.1.7.2")), signer_infos)
    return _seq(_oid("1.2.840.113549.1.7.2"), _ctx(0, signed_data))


def make_signed_pe_file(
    path: Path,
    *,
    blob: bytes | None = None,
    magic: int = 0x20B,
    table_size_zero: bool = False,
    wrap: bool = True,
) -> Path:
    """Write a minimal PE whose security directory points at the table.

    With ``wrap=True`` (default) the DER ``blob`` is wrapped in a standard
    8-byte ``WIN_CERTIFICATE`` header (revision 0x0200, type 0x0002); pass
    ``wrap=False`` to place hand-built table bytes verbatim.
    """
    der = blob if blob is not None else build_signed_data_blob()
    if wrap:
        payload = struct.pack("<IHH", 8 + len(der), 0x0200, 0x0002) + der
    else:
        payload = der
    if not magic:
        header = b"MZ" + bytes(0x3E)
        path.write_bytes(header)
        return path
    e_lfanew = 0x80
    coff = e_lfanew + 4
    optional_start = coff + 20
    dir_offset = optional_start + (112 if magic == 0x20B else 96)
    security_dir = dir_offset + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4
    cert_offset = security_dir + 8 + 64  # leave slack; table appended after header
    header = bytearray(cert_offset)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    header[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", header, coff + 16, 240)  # SizeOfOptionalHeader
    struct.pack_into("<H", header, coff + 20, magic)
    size = 0 if table_size_zero else len(payload)
    struct.pack_into("<II", header, security_dir, cert_offset, size)
    path.write_bytes(bytes(header) + payload)
    return path
# ---- SignedData parse-back (the mission recipe, verified field by field) --------


def test_minimal_signed_data_parses_back_fully() -> None:
    blob = build_signed_data_blob()
    signed, signers = parse_pkcs7_signed_data(blob)
    assert signed is True
    assert len(signers) == 1
    signer = signers[0]
    assert signer.index == 0
    assert signer.serial_hex == "123456789abcdef"
    assert signer.digest_algorithm == "sha256"
    assert signer.signature_algorithm == "sha256WithRSAEncryption"
    assert signer.signing_time == "2023-05-17T12:30:00Z"
    assert signer.sid_kind == "issuerAndSerialNumber"


def test_two_signers_shift_serials() -> None:
    blob = build_signed_data_blob(signer_count=2)
    _, signers = parse_pkcs7_signed_data(blob)
    assert [signer.serial_hex for signer in signers] == [
        "123456789abcdef",
        "123456789abcdf0",
    ]


def test_signer_without_signed_attrs_has_no_time() -> None:
    blob = build_signed_data_blob(with_signed_attrs=False)
    _, signers = parse_pkcs7_signed_data(blob)
    assert signers[0].signing_time is None


def test_generalized_time_and_ecdsa_names() -> None:
    blob = build_signed_data_blob(
        utctime_text="20230517123000Z",
        digest_oid="2.16.840.1.101.3.4.2.3",
        signature_oid="1.2.840.10045.4.3.4",
    )
    _, signers = parse_pkcs7_signed_data(blob)
    assert signers[0].signing_time == "2023-05-17T12:30:00Z"
    assert signers[0].digest_algorithm == "sha512"
    assert signers[0].signature_algorithm == "ecdsa-with-SHA512"


def test_unknown_oids_stay_dotted() -> None:
    blob = build_signed_data_blob(digest_oid="1.2.3.4.5", signature_oid="1.2.3.4.6")
    _, signers = parse_pkcs7_signed_data(blob)
    assert signers[0].digest_algorithm == "1.2.3.4.5"
    assert signers[0].signature_algorithm == "1.2.3.4.6"


def test_multi_byte_oid_components_round_trip() -> None:
    blob = build_signed_data_blob(digest_oid="2.16.840.1.101.3.4.2.1")
    _, signers = parse_pkcs7_signed_data(blob)
    assert signers[0].digest_algorithm == "sha256"


def test_signer_limit_is_bounded_and_warns() -> None:
    blob = build_signed_data_blob(signer_count=MAX_SIGNERS + 2)
    _, signers = parse_pkcs7_signed_data(blob)
    assert len(signers) == MAX_SIGNERS


# ---- malformed DER: typed AnalysisError -----------------------------------------


def test_content_info_must_be_a_sequence() -> None:
    with pytest.raises(AnalysisError, match="ContentInfo is not a SEQUENCE"):
        parse_pkcs7_signed_data(_tlv(0x04, b"x"))


def test_truncated_der_header_is_typed_error() -> None:
    with pytest.raises(AnalysisError, match="truncated header"):
        parse_pkcs7_signed_data(b"\x30")


def test_indefinite_length_is_typed_error() -> None:
    with pytest.raises(AnalysisError, match="indefinite length"):
        parse_pkcs7_signed_data(b"\x30\x80\x00")


def test_overlong_length_claim_is_typed_error() -> None:
    with pytest.raises(AnalysisError, match="claims 65281 byte"):
        parse_pkcs7_signed_data(_tlv(0x30, b"\x02\x82\xff\x01\x02"))


def test_high_tag_number_is_typed_error() -> None:
    with pytest.raises(AnalysisError, match="high-tag-number"):
        parse_pkcs7_signed_data(b"\x1f\x05\x02\x01\x01")


def test_excessive_length_octets_are_typed_error() -> None:
    with pytest.raises(AnalysisError, match="length octet count 5 is excessive"):
        parse_pkcs7_signed_data(_tlv(0x30, b"\x02\x85\x01\x02\x03\x04\x05"))


def test_truncated_length_octets_are_typed_error() -> None:
    with pytest.raises(AnalysisError, match="truncated length"):
        parse_pkcs7_signed_data(_tlv(0x30, b"\x02\x84\x01"))


def test_missing_content_type_wrapping_is_typed_error() -> None:
    inner = _seq(_int(1), _setof(_seq(_oid("1.3.14.3.2.26"))), _setof())
    blob = _seq(_oid("1.2.840.113549.1.7.2"), _seq(inner))  # SEQUENCE, not [0]
    with pytest.raises(AnalysisError, match="context-\\[0\\] wrapper"):
        parse_pkcs7_signed_data(blob)


def test_signed_data_with_too_few_fields_is_typed_error() -> None:
    blob = _seq(_oid("1.2.840.113549.1.7.2"), _ctx(0, _seq(_int(1), _int(1))))
    with pytest.raises(AnalysisError, match="needs version, algorithms, signerInfos"):
        parse_pkcs7_signed_data(blob)


def test_signed_data_without_signerinfos_is_typed_error() -> None:
    signed = _seq(_int(1), _tlv(0x30, b""), _tlv(0x30, b""))
    blob = _seq(_oid("1.2.840.113549.1.7.2"), _ctx(0, signed))
    with pytest.raises(AnalysisError, match="lacks a signerInfos SET"):
        parse_pkcs7_signed_data(blob)


def test_content_type_must_be_oid() -> None:
    blob = _seq(_int(1), _ctx(0, _seq(_int(1), _setof(), _setof())))
    with pytest.raises(AnalysisError, match="contentType is not an OBJECT IDENTIFIER"):
        parse_pkcs7_signed_data(blob)


def test_non_pkcs7_content_type_is_skipped_not_raised() -> None:
    blob = _seq(_oid("1.2.840.113549.1.7.1"), _ctx(0, b""))
    warnings: list[str] = []
    signed, signers = parse_pkcs7_signed_data(blob, warnings)
    assert signed is False
    assert signers == ()
    assert any("not PKCS#7 signedData" in warning for warning in warnings)

# ---- SignerInfo-level malformed cases ------------------------------------------


def _signed_data_with_signer(signer: bytes) -> bytes:
    signed = _seq(
        _int(1),
        _setof(_seq(_oid("1.3.14.3.2.26"))),
        _seq(_oid("1.2.840.113549.1.7.2")),
        _setof(signer),
    )
    return _seq(_oid("1.2.840.113549.1.7.2"), _ctx(0, signed))


def test_signer_with_too_few_fields_is_typed_error() -> None:
    blob = _signed_data_with_signer(_seq(_int(1), _int(2), _int(3)))
    with pytest.raises(AnalysisError, match="has only 3 top-level field"):
        parse_pkcs7_signed_data(blob)


def test_signer_with_unknown_sid_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _int(7),
        _seq(_oid("1.3.14.3.2.26")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="unknown sid"):
        parse_pkcs7_signed_data(blob)


def test_signer_with_missing_signature_octets_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _seq(_oid("1.3.14.3.2.26")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _setof(b"x"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="signature is not an OCTET STRING"):
        parse_pkcs7_signed_data(blob)


def test_signer_without_signature_fields_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _seq(_oid("1.3.14.3.2.26")),
        _ctx(0, _seq(_oid("1.2.840.113549.1.9.5"), _setof(_utctime("230517123000Z")))),
        _seq(_oid("1.2.840.113549.1.1.1")),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="lacks the signature OCTET STRING"):
        parse_pkcs7_signed_data(blob)


def test_algorithm_identifier_without_oid_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _seq(),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"sig"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="AlgorithmIdentifier without an OID"):
        parse_pkcs7_signed_data(blob)


def test_algorithm_identifier_must_be_sequence() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _oid("1.3.14.3.2.26"),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"sig"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="expected AlgorithmIdentifier SEQUENCE"):
        parse_pkcs7_signed_data(blob)

# ---- attribute / sid variants ---------------------------------------------------


def test_empty_oid_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _seq(_tlv(0x06, b"")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"sig"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="empty OBJECT IDENTIFIER"):
        parse_pkcs7_signed_data(blob)


def test_truncated_oid_component_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(0xABC)),
        _seq(_tlv(0x06, b"\x2a\x86")),  # ends mid-continuation
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"sig"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="truncated OID component"):
        parse_pkcs7_signed_data(blob)


def test_empty_integer_is_typed_error() -> None:
    signer = _seq(
        _int(1),
        _seq(_tlv(0x02, b"")),  # Name then an empty serial INTEGER
        _seq(_oid("1.3.14.3.2.26")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"sig"),
    )
    blob = _signed_data_with_signer(signer)
    with pytest.raises(AnalysisError, match="empty INTEGER"):
        parse_pkcs7_signed_data(blob)


def test_signerinfos_member_that_is_not_a_sequence_is_skipped() -> None:
    good_signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(9)),
        _seq(_oid("1.3.14.3.2.26")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    signed = _seq(
        _int(1),
        _setof(_seq(_oid("1.3.14.3.2.26"))),
        _seq(_oid("1.2.840.113549.1.7.2")),
        _setof(_octet(b"junk"), good_signer),
    )
    blob = _seq(_oid("1.2.840.113549.1.7.2"), _ctx(0, signed))
    warnings: list[str] = []
    _, signers = parse_pkcs7_signed_data(blob, warnings)
    assert len(signers) == 1
    assert any("not a SignerInfo SEQUENCE" in warning for warning in warnings)


def test_signing_time_attribute_variants() -> None:
    warnings: list[str] = []
    # A SET value without any time inside -> warning, signing_time None.
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(1)),
        _seq(_oid("1.3.14.3.2.26")),
        _ctx(0, _seq(_oid("1.2.840.113549.1.9.5"), _setof(_octet(b"nope")))),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    _, signers = parse_pkcs7_signed_data(_signed_data_with_signer(signer), warnings)
    assert signers[0].signing_time is None
    assert any("without a time value" in warning for warning in warnings)
    # An attribute whose first field is not an OID -> warning.
    warnings.clear()
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(1)),
        _seq(_oid("1.3.14.3.2.26")),
        _ctx(0, _seq(_int(5), _setof(_utctime("230517123000Z")))),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    _, signers = parse_pkcs7_signed_data(_signed_data_with_signer(signer), warnings)
    assert signers[0].signing_time is None
    assert any("lacks an OID" in warning for warning in warnings)
    # An attribute that is not a SEQUENCE -> warning.
    warnings.clear()
    signer = _seq(
        _int(1),
        _seq(_seq(_oid("2.5.4.3")), _int(1)),
        _seq(_oid("1.3.14.3.2.26")),
        _ctx(0, _octet(b"junk")),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    _, signers = parse_pkcs7_signed_data(_signed_data_with_signer(signer), warnings)
    assert any("attribute is not a SEQUENCE" in warning for warning in warnings)


def test_subject_key_identifier_sid_and_odd_time_strings() -> None:
    signer = _seq(
        _int(1),
        _ctx(0, _octet(b"\x11" * 20), constructed=False),
        _seq(_oid("1.3.14.3.2.26")),
        _ctx(0, _seq(_oid("1.2.840.113549.1.9.5"), _setof(_utctime("NOT-A-TIME!")))),
        _seq(_oid("1.2.840.113549.1.1.1")),
        _octet(b"s"),
    )
    _, signers = parse_pkcs7_signed_data(_signed_data_with_signer(signer))
    assert signers[0].sid_kind == "subjectKeyIdentifier"
    assert signers[0].serial_hex is None
    assert signers[0].signing_time == "NOT-A-TIME!"

# ---- PE certificate table walker ------------------------------------------------


def test_pe_table_present_parses_the_signer(tmp_path: Path) -> None:
    pe = make_signed_pe_file(tmp_path / "signed.exe")
    result = inspect_cert_table(pe)
    assert result.path == str(pe)
    assert result.table_present is True
    assert result.status == "present"
    assert result.entries == 1
    assert result.revision == pe_certs.WIN_CERT_REVISION_2_0
    assert result.certificate_type == pe_certs.WIN_CERT_TYPE_PKCS_SIGNED_DATA
    assert result.signed_data is True
    assert result.signer_count == 1
    assert result.signers[0].serial_hex == "123456789abcdef"
    assert result.gaps == ("issuer name not decoded",)
    assert result.evidence.source == "cert.pe"
    assert result.evidence.confidence == pe_certs.Confidence.HIGH
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_pe32_magic_is_supported(tmp_path: Path) -> None:
    pe = make_signed_pe_file(tmp_path / "signed32.exe", magic=0x10B)
    result = inspect_cert_table(pe)
    assert result.status == "present"
    assert result.signer_count == 1


def test_pe_absent_table(tmp_path: Path) -> None:
    pe = make_signed_pe_file(tmp_path / "unsigned.exe", table_size_zero=True)
    result = inspect_cert_table(pe)
    assert result.table_present is False
    assert result.status == "absent"
    assert result.signers == ()
    assert result.gaps == ()
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_pe_malformed_dwlength_is_reported_not_raised(tmp_path: Path) -> None:
    blob = build_signed_data_blob()
    table = struct.pack("<IHH", 4, 0x0200, 0x0002) + blob  # dwLength < 8
    pe = make_signed_pe_file(tmp_path / "broken.exe", blob=table, wrap=False)
    result = inspect_cert_table(pe)
    assert result.status == "malformed"
    assert result.entries == 0
    assert any("impossible dwLength" in warning for warning in result.warnings)


def test_pe_unsupported_entry_type_is_skipped(tmp_path: Path) -> None:
    blob = build_signed_data_blob()
    entry = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0004) + blob
    pe = make_signed_pe_file(tmp_path / "other.exe", blob=entry, wrap=False)
    result = inspect_cert_table(pe)
    assert result.status == "present"
    assert result.entries == 1
    assert result.signers == ()
    assert result.signed_data is False
    assert any("not PKCS_SIGNED_DATA" in warning for warning in result.warnings)


def test_pe_table_with_two_entries_and_padding(tmp_path: Path) -> None:
    blob = build_signed_data_blob()
    first = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    padded = first + bytes((-len(first)) % 8)
    pe = make_signed_pe_file(tmp_path / "two.exe", blob=padded, wrap=False)
    result = inspect_cert_table(pe)
    assert result.entries == 1
    assert result.signer_count == 1


def test_pe_entry_cap_is_bounded(tmp_path: Path) -> None:
    blob = build_signed_data_blob()
    entry = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    padded = entry + bytes((-len(entry)) % 8)
    pe = make_signed_pe_file(
        tmp_path / "many.exe", blob=padded * (MAX_CERT_ENTRIES + 2), wrap=False
    )
    result = inspect_cert_table(pe)
    assert result.entries == MAX_CERT_ENTRIES
    assert any("entry limit" in warning for warning in result.warnings)


def test_pe_entry_cap_zero_length_table_body_is_malformed(tmp_path: Path) -> None:
    pe = make_signed_pe_file(tmp_path / "tiny.exe", blob=bytes(4), wrap=False)
    result = inspect_cert_table(pe)
    assert result.status == "malformed"


def build_signed_pe_headerless_table(blob: bytes, *, claimed_size: int) -> bytes:
    """A WIN_CERTIFICATE entry whose dwLength claims more than the file has."""
    return struct.pack("<IHH", 8 + claimed_size, 0x0200, 0x0002) + blob

def test_pe_table_extending_past_eof_is_clamped(tmp_path: Path) -> None:
    blob = build_signed_data_blob()
    payload = build_signed_pe_headerless_table(blob, claimed_size=len(blob) + 64)
    pe = make_signed_pe_file(tmp_path / "clamp.exe", blob=payload, wrap=False)
    result = inspect_cert_table(pe)
    assert result.status == "present"
    assert result.signer_count == 1
    assert any("extends past the table" in warning for warning in result.warnings)


# ---- PE header-level typed errors -----------------------------------------------


def test_not_a_pe_missing_magic(tmp_path: Path) -> None:
    target = tmp_path / "plain.bin"
    target.write_bytes(b"ELFMORELIKEANELF" * 8)
    with pytest.raises(AnalysisError, match="missing MZ magic"):
        inspect_cert_table(target)


def test_not_a_pe_missing_pe_signature(tmp_path: Path) -> None:
    target = tmp_path / "fake.exe"
    target.write_bytes(b"MZ" + bytes(0x3E))
    with pytest.raises(AnalysisError, match="signature not found"):
        inspect_cert_table(target)


def test_pe_without_optional_header(tmp_path: Path) -> None:
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    target = tmp_path / "noopt.exe"
    target.write_bytes(bytes(data))
    with pytest.raises(AnalysisError, match="optional header is absent"):
        inspect_cert_table(target)


def test_pe_with_unknown_optional_magic(tmp_path: Path) -> None:
    data = bytearray(0x180)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x80 + 4 + 16, 240)
    struct.pack_into("<H", data, 0x80 + 4 + 20, 0x107)  # ROM image
    target = tmp_path / "rom.exe"
    target.write_bytes(bytes(data))
    with pytest.raises(AnalysisError, match="unsupported optional header magic 0x107"):
        inspect_cert_table(target)


def test_pe_truncated_before_security_directory(tmp_path: Path) -> None:
    data = bytearray(0x120)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x80 + 4 + 16, 240)
    struct.pack_into("<H", data, 0x80 + 4 + 20, 0x20B)
    target = tmp_path / "short.exe"
    target.write_bytes(bytes(data))
    with pytest.raises(AnalysisError, match="truncated before the security directory"):
        inspect_cert_table(target)


def test_parse_certificate_table_requires_bytes() -> None:
    with pytest.raises(AnalysisError, match="data must be bytes"):
        parse_certificate_table("MZ")  # type: ignore[arg-type]


def test_inspect_missing_file_is_typed_error(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="file not found"):
        inspect_cert_table(tmp_path / "ghost.exe")


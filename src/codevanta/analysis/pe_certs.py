"""Pure-Python PE certificate table walker (IMAGE_DIRECTORY_ENTRY_SECURITY).

No external tool, no dependencies: the security data directory of a PE file
points at a certificate table of ``WIN_CERTIFICATE`` entries, and each
``PKCS_SIGNED_DATA`` entry carries a PKCS#7 ``SignedData`` blob. This module
hand-rolls a minimal DER reader (tag, length, one level of children at a
time) and walks exactly the signed-data structure: ``ContentInfo`` ->
``SignedData`` -> ``SignerInfo`` entries. From it the walker reports the
signer count, each signer's serial number (hex), the digest and signature
algorithm OID names for the common SHA-1/256/384/512 RSA/ECDSA OIDs, and the
``signingTime`` UTCTime/GeneralizedTime when the signer carries it in its
authenticated attributes.

Honesty rules: structure findings are HIGH confidence (they are read straight
out of the file), the issuer Name is *never* decoded (X.500 name parsing is
out of scope and reported as an explicit gap), and the module never verifies
trust chains -- it parses, it does not vouch. Malformed DER raises the typed
:class:`~codevanta.core.report.AnalysisError`; a missing or header-broken
certificate table is reported honestly (``absent``/``malformed`` status)
rather than raised.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "EVIDENCE_SOURCE",
    "MAX_CERT_ENTRIES",
    "MAX_SIGNERS",
    "CertSigner",
    "PeCertResult",
    "inspect_cert_table",
    "parse_certificate_table",
    "parse_pkcs7_signed_data",
]

#: Evidence ``source`` id for this lane.
EVIDENCE_SOURCE = "cert.pe"

#: SignerInfo entries kept per parse (bounded work).
MAX_SIGNERS = 16

#: ``WIN_CERTIFICATE`` entries walked per table (bounded work).
MAX_CERT_ENTRIES = 8

#: Ceiling on warnings kept per result.
MAX_WARNINGS = 32

#: ASN.1 universal tag NUMBERS (the low 5 bits of the identifier octet) this
#: walker understands. SEQUENCE is 0x10 (byte 0x30 = constructed SEQUENCE).
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x10
TAG_SET = 0x11

#: ASN.1 context class bits (constructed context-[n] tags).
CLASS_CONTEXT = 0x80
FLAG_CONSTRUCTED = 0x20

#: ``SignedData`` content type OID (PKCS#7).
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"

#: ``signingTime`` authenticated-attribute OID (PKCS#9).
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"

#: Common digest-algorithm OIDs -> friendly names (unknown OIDs stay dotted).
OID_DIGEST_NAMES: dict[str, str] = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

#: Common signature-algorithm OIDs -> friendly names (unknown OIDs stay dotted).
OID_SIGNATURE_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.2.1": "ecdsa",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

#: ``WIN_CERTIFICATE.wRevision`` values.
WIN_CERT_REVISION_1_0 = 0x0100
WIN_CERT_REVISION_2_0 = 0x0200

#: ``WIN_CERTIFICATE.wCertificateType`` values (only 0x0002 is DER-parsed).
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

#: The one gap this walker admits by design.
GAP_ISSUER_NOT_DECODED = "issuer name not decoded"


def _note(warnings: list[str], message: str) -> None:
    """Append ``message`` once, summarising away everything past the cap."""
    if message in warnings:
        return
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)
    elif warnings and not warnings[-1].endswith("..."):
        warnings.append(f"{MAX_WARNINGS}+ warnings; further messages dropped...")


@dataclass(frozen=True)
class DerElement:
    """One parsed DER TLV: tag, class, and the span of its content bytes."""

    tag: int
    tag_class: int
    constructed: bool
    start: int  # first content byte
    end: int  # one past the last content byte
    next: int  # offset of the following element

    @property
    def is_context(self) -> bool:
        """Whether the tag is a context-class tag (``[n]``)."""
        return bool(self.tag_class & CLASS_CONTEXT)


@dataclass(frozen=True)
class CertSigner:
    """One ``SignerInfo`` of a PKCS#7 ``SignedData`` structure."""

    index: int
    serial_hex: str | None = None
    digest_algorithm: str = ""
    signature_algorithm: str = ""
    signing_time: str | None = None
    sid_kind: str = "issuerAndSerialNumber"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "serial_hex": self.serial_hex,
            "digest_algorithm": self.digest_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "signing_time": self.signing_time,
            "sid_kind": self.sid_kind,
        }

@dataclass(frozen=True)
class PeCertResult:
    """Typed verdict on one PE file's certificate table."""

    path: str | None = None
    table_present: bool = False
    status: str = "absent"
    entries: int = 0
    revision: int | None = None
    certificate_type: int | None = None
    signed_data: bool = False
    signers: tuple[CertSigner, ...] = ()
    warnings: list[str] = field(default_factory=list)
    gaps: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source=EVIDENCE_SOURCE,
            method="certificate_table",
            confidence=Confidence.HIGH,
        )
    )

    @property
    def signer_count(self) -> int:
        """Number of SignerInfo structures parsed (bounded by MAX_SIGNERS)."""
        return len(self.signers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "table_present": self.table_present,
            "status": self.status,
            "entries": self.entries,
            "revision": self.revision,
            "certificate_type": self.certificate_type,
            "signed_data": self.signed_data,
            "signers": [signer.to_dict() for signer in self.signers],
            "signer_count": self.signer_count,
            "warnings": list(self.warnings),
            "gaps": list(self.gaps),
            "evidence": self.evidence.to_dict(),
        }


# ---- minimal hand-rolled DER primitives -------------------------------------


def _parse_element(data: bytes, offset: int, end: int) -> DerElement:
    """Read one DER TLV header at ``offset``; raise on malformed DER."""
    if offset + 2 > end:
        raise AnalysisError(f"malformed DER at offset {offset}: truncated header")
    first = data[offset]
    if first & 0x1F == 0x1F:
        raise AnalysisError(
            f"malformed DER at offset {offset}: high-tag-number tags are not supported"
        )
    length_offset = offset + 1
    length_byte = data[length_offset]
    if length_byte == 0x80:
        raise AnalysisError(
            f"malformed DER at offset {offset}: indefinite length is not valid DER"
        )
    if length_byte < 0x80:
        length = length_byte
        content_start = length_offset + 1
    else:
        count = length_byte & 0x7F
        if count > 4:
            raise AnalysisError(
                f"malformed DER at offset {offset}: length octet count {count} is excessive"
            )
        if length_offset + 1 + count > end:
            raise AnalysisError(f"malformed DER at offset {offset}: truncated length")
        length = int.from_bytes(data[length_offset + 1 : length_offset + 1 + count], "big")
        content_start = length_offset + 1 + count
    content_end = content_start + length
    if content_end > end:
        raise AnalysisError(
            f"malformed DER at offset {offset}: content claims {length} byte(s) "
            f"but only {end - content_start} remain"
        )
    return DerElement(
        tag=first & 0x1F,
        tag_class=first & 0xE0,
        constructed=bool(first & FLAG_CONSTRUCTED),
        start=content_start,
        end=content_end,
        next=content_end,
    )


def _parse_children(data: bytes, start: int, end: int) -> tuple[DerElement, ...]:
    """Parse consecutive sibling TLVs covering exactly ``[start, end)``."""
    elements: list[DerElement] = []
    offset = start
    while offset < end:
        element = _parse_element(data, offset, end)
        elements.append(element)
        offset = element.next
    return tuple(elements)


def _parse_oid(data: bytes, start: int, end: int) -> str:
    """Decode one OBJECT IDENTIFIER content into dotted-decimal form."""
    if start >= end:
        raise AnalysisError("malformed DER: empty OBJECT IDENTIFIER content")
    first = data[start]
    if first < 80:
        parts = [str(first // 40), str(first % 40)]
    else:
        parts = ["2", str(first - 80)]
    value = 0
    for byte in data[start + 1 : end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    if value:
        raise AnalysisError("malformed DER: truncated OID component")
    return ".".join(parts)


def _parse_integer(data: bytes, start: int, end: int) -> int:
    """Decode one INTEGER content (big-endian, arbitrary width)."""
    if start >= end:
        raise AnalysisError("malformed DER: empty INTEGER content")
    return int.from_bytes(data[start:end], "big")


def _parse_time(data: bytes, start: int, end: int) -> str:
    """Decode UTCTime/GeneralizedTime content; keep anything else verbatim."""
    text = data[start:end].decode("ascii", errors="replace")
    if len(text) == 13 and text.endswith("Z") and text[:12].isdigit():
        yy = int(text[:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        return (
            f"{year:04d}-{text[2:4]}-{text[4:6]}"
            f"T{text[6:8]}:{text[8:10]}:{text[10:12]}Z"
        )
    if len(text) == 15 and text.endswith("Z") and text[:14].isdigit():
        return (
            f"{text[0:4]}-{text[4:6]}-{text[6:8]}"
            f"T{text[8:10]}:{text[10:12]}:{text[12:14]}Z"
        )
    return text
# ---- PKCS#7 SignedData structure walk ---------------------------------------


def _algorithm_name(data: bytes, element: DerElement, table: dict[str, str]) -> str:
    """Read an AlgorithmIdentifier SEQUENCE's OID; name it or keep it dotted."""
    if element.tag != TAG_SEQUENCE:
        raise AnalysisError(
            f"malformed DER at offset {element.start}: expected AlgorithmIdentifier SEQUENCE"
        )
    children = _parse_children(data, element.start, element.end)
    if not children or children[0].tag != TAG_OID:
        raise AnalysisError("malformed DER: AlgorithmIdentifier without an OID")
    oid = _parse_oid(data, children[0].start, children[0].end)
    return table.get(oid, oid)


def _find_signing_time(
    data: bytes, attrs: DerElement, warnings: list[str]
) -> str | None:
    """Find ``signingTime`` (PKCS#9 1.2.840.113549.1.9.5) in a SET of attributes."""
    for attribute in _parse_children(data, attrs.start, attrs.end):
        if attribute.tag != TAG_SEQUENCE:
            _note(warnings, "authenticated attribute is not a SEQUENCE; skipped")
            continue
        fields = _parse_children(data, attribute.start, attribute.end)
        if len(fields) < 2 or fields[0].tag != TAG_OID:
            _note(warnings, "authenticated attribute lacks an OID; skipped")
            continue
        oid = _parse_oid(data, fields[0].start, fields[0].end)
        if oid != OID_SIGNING_TIME:
            continue
        for value in _parse_children(data, fields[1].start, fields[1].end):
            if value.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
                return _parse_time(data, value.start, value.end)
        _note(warnings, "signingTime attribute without a time value")
    return None
def _parse_signer(
    data: bytes, element: DerElement, index: int, warnings: list[str]
) -> CertSigner:
    """Walk one ``SignerInfo`` SEQUENCE into a typed :class:`CertSigner`."""
    fields = _parse_children(data, element.start, element.end)
    if len(fields) < 5:
        raise AnalysisError(
            f"malformed DER: SignerInfo {index} has only {len(fields)} top-level field(s)"
        )
    serial_hex: str | None = None
    sid_kind = "issuerAndSerialNumber"
    sid = fields[1]
    if sid.tag == TAG_SEQUENCE:
        sid_children = _parse_children(data, sid.start, sid.end)
        for child in sid_children:
            if child.tag == TAG_INTEGER:
                serial = _parse_integer(data, child.start, child.end)
                serial_hex = f"{serial:x}"
                break
    elif sid.is_context:
        sid_kind = "subjectKeyIdentifier"
    else:
        raise AnalysisError(f"malformed DER: SignerInfo {index} has an unknown sid")
    digest_algorithm = _algorithm_name(data, fields[2], OID_DIGEST_NAMES)
    signing_time: str | None = None
    cursor = 3
    attrs = fields[cursor]
    if attrs.is_context and attrs.constructed:
        signing_time = _find_signing_time(data, attrs, warnings)
        cursor += 1
    if cursor >= len(fields):
        raise AnalysisError(f"malformed DER: SignerInfo {index} lacks signature fields")
    signature_algorithm = _algorithm_name(data, fields[cursor], OID_SIGNATURE_NAMES)
    cursor += 1
    if cursor >= len(fields):
        raise AnalysisError(
            f"malformed DER: SignerInfo {index} lacks the signature OCTET STRING"
        )
    if fields[cursor].tag != TAG_OCTET_STRING:
        raise AnalysisError(
            f"malformed DER: SignerInfo {index} signature is not an OCTET STRING"
        )
    return CertSigner(
        index=index,
        serial_hex=serial_hex,
        digest_algorithm=digest_algorithm,
        signature_algorithm=signature_algorithm,
        signing_time=signing_time,
        sid_kind=sid_kind,
    )


def parse_pkcs7_signed_data(
    blob: bytes, warnings: list[str] | None = None
) -> tuple[bool, tuple[CertSigner, ...]]:
    """Walk a PKCS#7 ``SignedData`` blob; return (is_signed_data, signers).

    Pure structure walk over ``ContentInfo -> [0] SignedData -> signerInfos``:
    signer count, serial numbers, algorithm OID names and ``signingTime``
    only. Certificates and revocation lists are deliberately skipped
    uninterpreted, issuer Names are never decoded, and trust chains are never
    verified. Malformed DER raises the typed :class:`AnalysisError`.
    """
    warn = warnings if warnings is not None else []
    content_info = _parse_element(blob, 0, len(blob))
    if content_info.tag != TAG_SEQUENCE or not content_info.constructed:
        raise AnalysisError("malformed DER: ContentInfo is not a SEQUENCE")
    fields = _parse_children(blob, content_info.start, content_info.end)
    if len(fields) < 2:
        raise AnalysisError("malformed DER: ContentInfo needs a contentType and content")
    content_type = fields[0]
    if content_type.tag != TAG_OID:
        raise AnalysisError("malformed DER: contentType is not an OBJECT IDENTIFIER")
    if _parse_oid(blob, content_type.start, content_type.end) != OID_SIGNED_DATA:
        _note(warn, "certificate entry is not PKCS#7 signedData; structure skipped")
        return False, ()
    wrapped = fields[1]
    if not (wrapped.is_context and wrapped.constructed):
        raise AnalysisError("malformed DER: SignedData is not in a context-[0] wrapper")
    inner = _parse_children(blob, wrapped.start, wrapped.end)
    if len(inner) == 1 and inner[0].tag == TAG_SEQUENCE:
        # EXPLICIT [0] (the common, real-world form): the SignedData SEQUENCE
        # sits one level inside the wrapper.
        signed_fields = _parse_children(blob, inner[0].start, inner[0].end)
    else:
        # Tolerate the IMPLICIT form where the fields start directly.
        signed_fields = inner
    if len(signed_fields) < 3:
        raise AnalysisError(
            "malformed DER: SignedData needs version, algorithms, signerInfos"
        )
    signer_infos: DerElement | None = None
    # signerInfos is the trailing SET OF SignerInfo; digestAlgorithms is also
    # a SET, so scan from the end.
    for field_element in reversed(signed_fields):
        if field_element.tag == TAG_SET:
            signer_infos = field_element
            break
    if signer_infos is None:
        raise AnalysisError("malformed DER: SignedData lacks a signerInfos SET")
    signers: list[CertSigner] = []
    for index, signer_element in enumerate(
        _parse_children(blob, signer_infos.start, signer_infos.end)
    ):
        if len(signers) >= MAX_SIGNERS:
            _note(warn, f"signer limit {MAX_SIGNERS} reached; further signers dropped")
            break
        if signer_element.tag != TAG_SEQUENCE:
            _note(warn, "signerInfos member is not a SignerInfo SEQUENCE; skipped")
            continue
        signers.append(_parse_signer(blob, signer_element, index, warn))
    return True, tuple(signers)


# ---- PE certificate table walker --------------------------------------------


def _evidence_for(detail: str, confidence: Confidence) -> Evidence:
    """One certificate-table evidence record for the parsed verdict."""
    return Evidence(
        source=EVIDENCE_SOURCE,
        method="certificate_table",
        confidence=confidence,
        detail=detail,
    )


def _security_directory(data: bytes) -> tuple[int, int]:
    """Locate the IMAGE_DIRECTORY_ENTRY_SECURITY (va, size) pair.

    ``va`` of the security directory is a *file offset*, not an RVA -- the
    PE spec says so, and the walker reads exactly that.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise AnalysisError("not a PE file: missing MZ magic")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("not a PE file: PE\\0\\0 signature not found")
    coff = e_lfanew + 4
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    if optional_size == 0:
        raise AnalysisError("not a parseable PE: optional header is absent")
    magic = struct.unpack_from("<H", data, coff + 20)[0]
    optional_start = coff + 20  # the optional header follows the 20-byte COFF header
    if magic == 0x10B:  # PE32
        directories_offset = optional_start + 96
    elif magic == 0x20B:  # PE32+
        directories_offset = optional_start + 112
    else:
        raise AnalysisError(f"unsupported optional header magic 0x{magic:x}")
    security_dir = directories_offset + 4 * 8
    if security_dir + 8 > len(data):
        raise AnalysisError("optional header truncated before the security directory")
    offset, size = struct.unpack_from("<II", data, security_dir)
    return offset, size


def parse_certificate_table(data: bytes, source_path: str | None = None) -> PeCertResult:
    """Parse the certificate table of a PE image into a typed verdict.

    Walks at most :data:`MAX_CERT_ENTRIES` ``WIN_CERTIFICATE`` entries,
    DER-parses the ``PKCS_SIGNED_DATA`` ones via
    :func:`parse_pkcs7_signed_data`, and reports ``absent``/``present``/
    ``malformed`` status honestly. Header-level table damage (a ``dwLength``
    under 8, an entry running past EOF) is reported as ``malformed`` with
    warnings; damage *inside* the DER raises the typed error.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise AnalysisError(f"data must be bytes, got {type(data).__name__}")
    offset, size = _security_directory(data)
    if size == 0 or offset == 0:
        return PeCertResult(
            path=source_path,
            table_present=False,
            status="absent",
            gaps=(),
            warnings=[],
            evidence=_evidence_for("no certificate table", Confidence.HIGH),
        )
    warnings: list[str] = []
    table = data[offset : offset + size]
    if len(table) < size:
        _note(warnings, "certificate table extends past EOF; clamped to the file end")
    if len(table) < 8:
        return PeCertResult(
            path=source_path,
            table_present=True,
            status="malformed",
            warnings=warnings,
            evidence=_evidence_for("certificate table too small", Confidence.LOW),
        )
    signers: list[CertSigner] = []
    signed_data_seen = False
    entries = 0
    revision: int | None = None
    certificate_type: int | None = None
    malformed = False
    cursor = 0
    while cursor + 8 <= len(table):
        if entries >= MAX_CERT_ENTRIES:
            _note(warnings, f"entry limit {MAX_CERT_ENTRIES} reached; further entries dropped")
            break
        entry_length, entry_revision, entry_type = struct.unpack_from("<IHH", table, cursor)
        revision = revision or entry_revision
        certificate_type = certificate_type or entry_type
        if entry_length < 8:
            _note(warnings, f"entry {entries} has an impossible dwLength; table malformed")
            malformed = True
            break
        if cursor + entry_length > len(table):
            _note(warnings, f"entry {entries} extends past the table; clamped to the end")
            payload = table[cursor + 8 :]
            entry_length = len(payload) + 8
        else:
            payload = table[cursor + 8 : cursor + entry_length]
        if entry_revision == WIN_CERT_REVISION_2_0 and entry_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            signed, entry_signers = parse_pkcs7_signed_data(payload, warnings)
            signed_data_seen = signed_data_seen or signed
            for signer in entry_signers:
                if len(signers) >= MAX_SIGNERS:
                    _note(warnings, f"signer limit {MAX_SIGNERS} reached; further signers dropped")
                    break
                signers.append(signer)
        else:
            _note(
                warnings,
                f"entry {entries} has revision 0x{entry_revision:04x}/type "
                f"0x{entry_type:04x}; not PKCS_SIGNED_DATA, skipped",
            )
        entries += 1
        cursor += (entry_length + 7) // 8 * 8  # entries are 8-byte aligned
    if entries == 0 and not malformed:
        _note(warnings, "no complete certificate entry in the table")
        malformed = True
    status = "malformed" if malformed else "present"
    gaps = (GAP_ISSUER_NOT_DECODED,) if signers else ()
    detail = (
        f"status={status}, entries={entries}, signer(s)={len(signers)}"
        + (", signedData" if signed_data_seen else "")
    )
    return PeCertResult(
        path=source_path,
        table_present=True,
        status=status,
        entries=entries,
        revision=revision,
        certificate_type=certificate_type,
        signed_data=signed_data_seen,
        signers=tuple(signers),
        warnings=warnings,
        gaps=gaps,
        evidence=_evidence_for(detail, Confidence.HIGH if not malformed else Confidence.LOW),
    )


def inspect_cert_table(path: str | Path) -> PeCertResult:
    """Read one PE file and parse its certificate table (pure Python, offline)."""
    target = Path(path)
    if not target.is_file():
        raise AnalysisError(f"file not found: {target}")
    return parse_certificate_table(target.read_bytes(), source_path=str(target))


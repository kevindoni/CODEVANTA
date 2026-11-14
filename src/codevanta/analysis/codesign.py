"""Mach-O code-signature lite (lane-format2): structure only, never trust.

One entry point, :func:`inspect_codesign`, walks a thin Mach-O's load
commands to the ``LC_CODE_SIGNATURE`` command, then parses the embedded
SuperBlob (magic ``0xfade0cc0``): the bounded slot table, the code
directory's identifier, the entitlements plist (slot types 5/7; the blob is
found by its ``0xfade7171`` magic because Apple's xnu headers and the lane
spec disagree about the slot number) and a certificates *count* from the
CMS signature blob. Entitlements are the DER-wrapped (possibly
double-wrapped) plist Apple ships; the payload is located by searching for
``b'<plist'`` / ``b'bplist00'`` and decoded with :mod:`plistlib`.

Parse ONLY structure -- nothing here verifies hashes, trust chains or
signatures, and nothing is written back. Files without ``LC_CODE_SIGNATURE``
report ``None``; a signature that is present but malformed raises
:class:`~codevanta.core.report.AnalysisError`. Fat (multi-architecture)
binaries are refused with a typed error naming the limitation. Findings
carry :class:`~codevanta.evidence.models.Evidence` with the
``codesign.macho`` source id at ``high`` confidence once the SuperBlob
structure has been magic-verified.
"""

from __future__ import annotations

import plistlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_CERTIFICATES",
    "MAX_ENTITLEMENT_KEYS",
    "MAX_LOAD_COMMANDS",
    "MAX_SLOTS",
    "CodesignInfo",
    "inspect_codesign",
]

#: Mach-O load command holding the embedded signature's offset/size.
LC_CODE_SIGNATURE = 0x1D
#: Thin Mach-O magics (``MH_MAGIC``/``MH_MAGIC_64``) and their byte-swaps.
MACHO_MAGIC_32 = 0xFEEDFACE
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_CIGAM_32 = 0xCEFAEDFE
MACHO_CIGAM_64 = 0xCFFAEDFE
#: Fat multi-architecture magics -- parsed binaries are refused, not guessed.
FAT_MAGICS = (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA)
#: SuperBlob / blob magics (big-endian on disk).
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_ENTITLEMENTS = 0xFADE7171
#: Slot types named by xnu ``cs_blobs.h`` (the entitlements plist also shows
#: up under slot type 7 in the lane spec; the blob magic decides, not the type).
SLOT_NAMES: dict[int, str] = {
    0x0: "code-directory",
    0x1: "info-slot",
    0x2: "requirements",
    0x3: "resource-dir",
    0x4: "application",
    0x5: "entitlements",
    0x7: "entitlements-spec7",
    0x10000: "cms-signature",
    0x10001: "identification",
}
#: DER tags used by the CMS certificate-count walk.
DER_SEQUENCE = 0x30
DER_SET = 0x31
DER_OID = 0x06
DER_INTEGER = 0x02
DER_CONTEXT_0 = 0xA0

#: Load commands walked per Mach-O before refusing (bounded work).
MAX_LOAD_COMMANDS = 512
#: SuperBlob slot records kept (bounded output).
MAX_SLOTS = 16
#: Entitlements keys kept (bounded output).
MAX_ENTITLEMENT_KEYS = 32
#: Certificates counted inside one CMS blob (bounded work).
MAX_CERTIFICATES = 16
#: Hard ceiling on one code-signature blob held in memory.
MAX_SIGNATURE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class CodesignInfo:
    """Mach-O code-signature structure summary (no trust verification)."""

    macho_kind: str
    endian: str
    signature_offset: int
    signature_size: int
    slot_count: int
    slots: tuple[tuple[int, str, int, int], ...]  # (slot type, name, blob offset, blob length)
    slots_truncated: bool
    identifier: str | None
    team_id: str | None
    entitlements_keys: tuple[str, ...]
    entitlements_truncated: bool
    certificates_count: int | None
    warnings: list[str] = field(default_factory=list)
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source="codesign.macho",
            method="lc_codesign-superblob",
            confidence=Confidence.UNKNOWN,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "macho_kind": self.macho_kind,
            "endian": self.endian,
            "signature_offset": self.signature_offset,
            "signature_size": self.signature_size,
            "slot_count": self.slot_count,
            "slots": [
                {"type": slot_type, "name": name, "offset": offset, "length": length}
                for slot_type, name, offset, length in self.slots
            ],
            "slots_truncated": self.slots_truncated,
            "identifier": self.identifier,
            "team_id": self.team_id,
            "entitlements_keys": list(self.entitlements_keys),
            "entitlements_truncated": self.entitlements_truncated,
            "certificates_count": self.certificates_count,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- little helpers ------------------------------------------------------------


def _u32(data: bytes, offset: int, endian: str) -> int:
    return int(struct.unpack_from("<I" if endian == "little" else ">I", data, offset)[0])


def _cstr(blob: bytes, offset: int, limit: int = 128) -> str:
    """Read one NUL-terminated ASCII string, bounded; empty when out of range."""
    if not 0 <= offset < len(blob):
        return ""
    end = min(len(blob), offset + limit)
    cut = blob.find(b"\x00", offset, end)
    raw = blob[offset : end if cut == -1 else cut]
    return raw.decode("utf-8", errors="replace")


# ---- load commands --------------------------------------------------------------


def _macho_flavour(head: bytes) -> tuple[str, str] | None:
    """Classify the Mach-O magic: ``(kind, endian)`` or ``None`` when not Mach-O."""
    magic_le = struct.unpack_from("<I", head, 0)[0]
    if magic_le in (MACHO_MAGIC_32, MACHO_MAGIC_64):
        return ("macho32" if magic_le == MACHO_MAGIC_32 else "macho64"), "little"
    if magic_le in (MACHO_CIGAM_32, MACHO_CIGAM_64):
        return ("macho32" if magic_le == MACHO_CIGAM_32 else "macho64"), "big"
    if magic_le in FAT_MAGICS:
        raise AnalysisError(
            "fat (multi-architecture) Mach-O is not supported; run the lane on a thin slice"
        )
    return None


def _find_code_signature(handle: Any, size: int, kind: str, endian: str) -> tuple[int, int]:
    """Walk the load-command table to ``LC_CODE_SIGNATURE``; ``(-1, 0)`` when absent.

    The header (32 bytes for 64-bit, 28 for 32-bit) is followed by ``ncmds``
    load commands; anything malformed in the table itself is a typed error.
    """
    header_size = 32 if kind == "macho64" else 28
    handle.seek(0)
    head = handle.read(header_size)
    if len(head) < header_size:
        raise AnalysisError("truncated Mach-O header")
    ncmds = _u32(head, 16, endian)
    cursor = header_size
    for _ in range(min(ncmds, MAX_LOAD_COMMANDS)):
        if cursor + 8 > size:
            raise AnalysisError("truncated Mach-O load-command table")
        handle.seek(cursor)
        block = handle.read(16)
        if len(block) < 8:
            raise AnalysisError("truncated Mach-O load-command table")
        cmd = _u32(block, 0, endian)
        cmdsize = _u32(block, 4, endian)
        if cmdsize < 8 or cursor + cmdsize > size:
            raise AnalysisError(
                f"malformed load command at offset {cursor} (cmd 0x{cmd:x}, size {cmdsize})"
            )
        if cmd == LC_CODE_SIGNATURE:
            if len(block) < 16 or cmdsize < 16:
                raise AnalysisError(
                    f"LC_CODE_SIGNATURE at offset {cursor} is too small to carry dataoff/datasize"
                )
            dataoff = _u32(block, 8, endian)
            datasize = _u32(block, 12, endian)
            return dataoff, datasize
        cursor += cmdsize
    if ncmds > MAX_LOAD_COMMANDS:
        raise AnalysisError(
            f"Mach-O carries {ncmds} load commands; the lane refuses to walk more than "
            f"{MAX_LOAD_COMMANDS}"
        )
    return -1, 0


# ---- SuperBlob -------------------------------------------------------------------


def _parse_superblob(
    sig: bytes, warnings: list[str]
) -> tuple[int, list[tuple[int, str, int, int]], bool]:
    """Walk the SuperBlob index; returns ``(declared count, bounded slot rows, truncated)``."""
    if len(sig) < 12:
        raise AnalysisError("code signature blob is too small for a SuperBlob header")
    magic = _u32(sig, 0, ">")
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise AnalysisError(
            f"code signature magic 0x{magic:08x} is not a SuperBlob (expected 0xfade0cc0)"
        )
    length = _u32(sig, 4, ">")
    count = _u32(sig, 8, ">")
    if length < 12 + count * 8 or length > len(sig):
        raise AnalysisError(
            f"SuperBlob declares length {length} for {count} slots, which does not fit "
            f"the {len(sig)}-byte blob"
        )
    slots: list[tuple[int, str, int, int]] = []
    truncated = False
    for index in range(count):
        if index >= MAX_SLOTS:
            truncated = True
            warnings.append(f"slot limit {MAX_SLOTS} reached; further slots dropped")
            break
        base = 12 + index * 8
        slot_type = _u32(sig, base, ">")
        slot_offset = _u32(sig, base + 4, ">")
        if slot_type == 0x10000 and slot_offset < len(sig):
            # The CMS signature slot carries a raw DER ContentInfo: its length
            # lives in the DER TLV header, not in a blob header.
            tlv = _der_tlv(sig, slot_offset)
            if tlv is None:
                raise AnalysisError(
                    f"slot {index} (type 0x10000) carries a truncated DER payload"
                )
            blob_length = tlv[1] + tlv[2] - slot_offset
        else:
            if slot_offset + 8 > len(sig):
                raise AnalysisError(
                    f"slot {index} (type 0x{slot_type:x}) points past the blob"
                )
            blob_length = _u32(sig, slot_offset + 4, ">")
            if blob_length < 8:
                raise AnalysisError(
                    f"slot {index} (type 0x{slot_type:x}) declares {blob_length} bytes, "
                    "below the 8-byte blob header minimum"
                )
        if slot_offset + blob_length > len(sig):
            raise AnalysisError(
                f"slot {index} (type 0x{slot_type:x}) declares {blob_length} bytes, "
                "overrunning the SuperBlob"
            )
        blob_magic = _u32(sig, slot_offset, ">")
        if blob_magic == CSMAGIC_CODEDIRECTORY:
            name = "code-directory"
        elif blob_magic == CSMAGIC_ENTITLEMENTS:
            name = "entitlements"
        else:
            name = SLOT_NAMES.get(slot_type, f"slot-0x{slot_type:x}")
        slots.append((slot_type, name, slot_offset, blob_length))
    return count, slots, truncated


def _parse_code_directory(sig: bytes, slot_offset: int, blob_length: int) -> str:
    """Extract the bundle identifier from the CodeDirectory (slot type 0)."""
    if blob_length < 28 or _u32(sig, slot_offset, ">") != CSMAGIC_CODEDIRECTORY:
        raise AnalysisError("code-directory slot is too small for a CodeDirectory header")
    ident_offset = _u32(sig, slot_offset + 20, ">")
    identifier = _cstr(sig, slot_offset + ident_offset)
    if not identifier:
        raise AnalysisError("code-directory carries no identifier string")
    return identifier


# ---- entitlements ------------------------------------------------------------------


def _decode_entitlements(
    sig: bytes, slot_offset: int, blob_length: int
) -> tuple[tuple[str, ...], bool, str | None]:
    """Decode the entitlements plist; returns ``(bounded keys, truncated, team id)``."""
    payload = sig[slot_offset + 8 : slot_offset + blob_length]
    idx_xml = payload.find(b"<plist")
    idx_bplist = payload.find(b"bplist00")
    candidates = [idx for idx in (idx_xml, idx_bplist) if idx != -1]
    if not candidates:
        raise AnalysisError(
            "entitlements blob carries no plist payload (no b'<plist' or b'bplist00' found)"
        )
    start = min(candidates)
    try:
        document = plistlib.loads(payload[start:])
    except (plistlib.InvalidFileException, ExpatError) as exc:
        raise AnalysisError(f"entitlements plist is undecodable: {exc}") from exc
    if not isinstance(document, dict):
        raise AnalysisError(
            f"entitlements plist decodes to {type(document).__name__}; expected a dict"
        )
    keys = tuple(sorted(str(key) for key in document))
    truncated = len(keys) > MAX_ENTITLEMENT_KEYS
    team = document.get("com.apple.developer.team-identifier")
    team_id = team if isinstance(team, str) and team else None
    return keys[:MAX_ENTITLEMENT_KEYS], truncated, team_id


# ---- CMS certificates (count only) -------------------------------------------------


def _der_tlv(blob: bytes, offset: int) -> tuple[int, int, int] | None:
    """One DER TLV at ``offset``: ``(tag, content offset, content length)`` or ``None``."""
    if offset + 2 > len(blob):
        return None
    tag = blob[offset]
    cursor = offset + 1
    first = blob[cursor]
    cursor += 1
    if first & 0x80:
        width = first & 0x7F
        if width == 0 or width > 4 or cursor + width > len(blob):
            return None
        length = int.from_bytes(blob[cursor : cursor + width], "big")
        cursor += width
    else:
        length = first
    if cursor + length > len(blob):
        return None
    return tag, cursor, length


def _cms_certificate_count(blob: bytes, warnings: list[str]) -> int | None:
    """Count the certificates in a CMS ``ContentInfo`` blob; ``None`` when not decodable.

    Navigation only: ``ContentInfo -> OID pkcs7-signedData -> [0] -> SignedData
    -> ... -> [0] certificates (IMPLICIT SET)``; the count is the number of
    top-level TLVs inside the certificate set. No certificate is ever parsed
    and nothing is verified.
    """
    outer = _der_tlv(blob, 0)
    if outer is None or outer[0] != DER_SEQUENCE:
        return None
    oid = _der_tlv(blob, outer[1])
    if oid is None or oid[0] != DER_OID:
        return None
    explicit = _der_tlv(blob, oid[1] + oid[2])
    if explicit is None or explicit[0] != DER_CONTEXT_0:
        return None
    signed_data = _der_tlv(blob, explicit[1])
    if signed_data is None or signed_data[0] != DER_SEQUENCE:
        return None
    cursor = signed_data[1]
    end = signed_data[1] + signed_data[2]
    certificates: tuple[int, int, int] | None = None
    first_context: tuple[int, int, int] | None = None
    context_sets = 0
    while cursor < end:
        child = _der_tlv(blob, cursor)
        if child is None:
            break
        tag, content_offset, content_length = child
        if tag == DER_CONTEXT_0:
            context_sets += 1
            if first_context is None:
                first_context = child
            elif certificates is None:
                certificates = child  # [0] digestAlgorithms precedes [0] certificates
                break
        cursor = content_offset + content_length
    if certificates is None and first_context is not None and context_sets == 1:
        # Some signers omit digestAlgorithms; the single [0] is the certificates.
        certificates = first_context
    if certificates is None:
        return None
    count = 0
    cursor = certificates[1]
    limit = certificates[1] + certificates[2]
    inner = _der_tlv(blob, certificates[1])
    if (
        inner is not None
        and inner[0] == DER_SET
        and inner[1] + inner[2] == limit
    ):
        # Explicit-form [0]: an inner SET OF Certificate wraps the members.
        cursor = inner[1]
        limit = inner[1] + inner[2]
    while cursor < limit:
        certificate = _der_tlv(blob, cursor)
        if certificate is None:
            warnings.append("CMS certificate set ends mid-TLV; the count covers what was read")
            break
        count += 1
        cursor = certificate[1] + certificate[2]
        if count >= MAX_CERTIFICATES:
            warnings.append(
                f"certificate limit {MAX_CERTIFICATES} reached; further certificates not counted"
            )
            break
    return count


# ---- entry point --------------------------------------------------------------------


def inspect_codesign(path: str | Path) -> CodesignInfo | None:
    """Summarise a Mach-O's embedded code signature. ``None`` when unsigned.

    Structure only: the ``LC_CODE_SIGNATURE`` command's offset, the SuperBlob
    slot table (bounded 16), the code-directory identifier, the entitlements
    keys (bounded 32) and a certificate count from the CMS blob. Malformed
    signature structures raise :class:`AnalysisError`; binaries without a
    signature load command report ``None``.
    """
    p = Path(path)
    if p.is_dir():
        return None
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise AnalysisError(f"cannot stat {p}: {exc}") from exc
    if size == 0:
        raise AnalysisError(f"empty file: {p}")
    if size > MAX_SIGNATURE_BYTES:
        raise AnalysisError(
            f"{p} exceeds the {MAX_SIGNATURE_BYTES // (1024 * 1024)} MiB code-signature budget"
        )
    with p.open("rb") as handle:
        head = handle.read(32)
    if len(head) < 28:
        return None
    flavour = _macho_flavour(head)
    if flavour is None:
        return None
    kind, endian = flavour
    with p.open("rb") as handle:
        dataoff, datasize = _find_code_signature(handle, size, kind, endian)
    if dataoff < 0:
        return None
    if datasize <= 0 or dataoff + datasize > size:
        raise AnalysisError(
            f"LC_CODE_SIGNATURE names {datasize} bytes at offset {dataoff}, which does not "
            f"fit the {size}-byte file"
        )
    with p.open("rb") as handle:
        handle.seek(dataoff)
        sig = handle.read(min(datasize, MAX_SIGNATURE_BYTES))
    warnings: list[str] = []
    count, slots, slots_truncated = _parse_superblob(sig, warnings)
    identifier: str | None = None
    entitlements_keys: tuple[str, ...] = ()
    entitlements_truncated = False
    team_id: str | None = None
    certificates_count: int | None = None
    for slot_type, name, slot_offset, blob_length in slots:
        if name == "code-directory" and identifier is None:
            identifier = _parse_code_directory(sig, slot_offset, blob_length)
        elif name == "entitlements" and not entitlements_keys:
            entitlements_keys, entitlements_truncated, team_id = _decode_entitlements(
                sig, slot_offset, blob_length
            )
        elif slot_type == 0x10000 and certificates_count is None:
            certificates_count = _cms_certificate_count(
                sig[slot_offset : slot_offset + blob_length], warnings
            )
            if certificates_count is None:
                warnings.append("cms-signature blob is not decodable as CMS; no certificate count")
    if slots_truncated:
        warnings.append(f"slot limit {MAX_SLOTS} reached; the index is truncated")
    if entitlements_truncated:
        warnings.append(
            f"entitlements key limit {MAX_ENTITLEMENT_KEYS} reached; further keys dropped"
        )
    detail = f"{len(slots)}/{count} slots"
    if identifier:
        detail += f"; identifier {identifier}"
    if certificates_count is not None:
        detail += f"; {certificates_count} certificates"
    evidence = Evidence(
        source="codesign.macho",
        method="lc_codesign-superblob",
        confidence=Confidence.HIGH,
        detail=detail,
        extra={"macho_kind": kind, "endian": endian},
    )
    return CodesignInfo(
        macho_kind=kind,
        endian=endian,
        signature_offset=dataoff,
        signature_size=datasize,
        slot_count=count,
        slots=tuple(slots),
        slots_truncated=slots_truncated,
        identifier=identifier,
        team_id=team_id,
        entitlements_keys=entitlements_keys,
        entitlements_truncated=entitlements_truncated,
        certificates_count=certificates_count,
        warnings=warnings,
        evidence=evidence,
    )

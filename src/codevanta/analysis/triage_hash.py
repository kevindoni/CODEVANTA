"""Triage hashing: Mandiant-convention imphash and ssdeep-style fuzzy hashing.

Two first-pass ("triage") hashes for one file, pure stdlib, offline:

* **imphash** -- MD5 over the lowercase ``dll.function`` list of a PE import
  table in import-table order, the Mandiant convention used by VirusTotal
  pivoting and JPCERT's impfuzzy. See
  https://www.mandiant.com/resources/blog/tracking-malware-import-hashing.
  Only PE is hashed: this loader pairs ELF/Mach-O symbols without a reliable
  library pairing, and non-PE "imphash" variants would not interoperate with
  VirusTotal, so they are refused with a typed error instead of guessed.
* **Fuzzy hash** -- context-triggered piecewise hashing in the ssdeep family
  (https://github.com/ssdeep-project/ssdeep): a rolling window hash (window 7,
  Adler-style h1/h2 plus a shift/xor h3) splits the input into content-defined
  blocks; each block is reduced by a 32-bit FNV-1 step (prime 16777619) to one
  base64 character, producing a ``block_size:part1:part2`` signature where
  part2 uses double the block size. ``fuzzy_compare`` scores two signatures
  0-100 with the ssdeep edit-distance formula (common-substring gate, length
  scaling, run-of-3 elimination, small-blocksize clamp).

Algorithm fidelity (documented deviations from the ssdeep 2.14 binary):

* The engine replicates the classic ssdeep ``fuzzy.c`` streaming structure
  (dual part1/part2 accumulators, the ``j < SPAMSUM_LENGTH/2`` block-size
  halving loop, tail-char handling when the rolling sum is non-zero) with the
  constants mandated for this lane: ``MIN_BLOCK_SIZE`` 32768 (block sizes
  32768<<i, six of them, cap 1048576) and FNV-1 offset basis 2166136261.
* Upstream ssdeep binaries pick block sizes from the 3*2^k series and seed the
  block hash at 0x28021967, so signatures produced here do not compare as
  byte-identical strings against ssdeep-binary output; the signature *shape*
  and the compare semantics are the ssdeep ones. Signatures from this engine
  interoperate with each other (and parse in ssdeep tooling).

Guarantees:

* Bounded work: at most ``max_bytes`` (default 64 MiB, ceiling 512 MiB) read
  per file; at most the first 4096 imports enter the imphash digest. Every cap
  that fires is reported through ``truncated`` flags or warnings -- never
  silently.
* Literal digests (imphash, the fuzzy signature) are *certain* evidence; the
  0-100 similarity score is a *medium*-confidence heuristic judgement and says
  so in its evidence record.
* Malformed inputs (empty file, unwritable path, non-PE imphash target,
  malformed signature strings, out-of-range bounds) raise
    :class:`~codevanta.core.report.AnalysisError` naming what is missing.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_BYTES",
    "FNV_OFFSET_BASIS",
    "FNV_PRIME",
    "FUZZY_HASH_SOURCE",
    "FuzzyComparison",
    "FuzzyHashResult",
    "IMPORT_HASH_SOURCE",
    "ImportHashResult",
    "MAX_BLOCK_SIZE",
    "MAX_IMPORTS",
    "MAX_MAX_BYTES",
    "MAX_WARNINGS",
    "MIN_BLOCK_SIZE",
    "NUM_BLOCK_SIZES",
    "REPORT_SOURCE",
    "ROLLING_WINDOW",
    "SPAMSUM_LENGTH",
    "TriageHashReport",
    "block_size_for_length",
    "fuzzy_compare",
    "fuzzy_hash_bytes",
    "fuzzy_hash_file",
    "import_hash",
    "triage_hashes",
]

#: Length of each signature half (SPAMSUM_LENGTH in ssdeep's fuzzy.c).
SPAMSUM_LENGTH = 64

#: Rolling-hash window size (ROLLING_WINDOW in ssdeep's fuzzy.c).
ROLLING_WINDOW = 7

#: Smallest block size on this engine's ladder (the lane's mandated constant;
#: upstream ssdeep binaries start their ladder at 3).
MIN_BLOCK_SIZE = 32768

#: Number of block sizes on the ladder; the largest is 32768 << 5.
NUM_BLOCK_SIZES = 6

#: Largest block size this engine will select (bounded work).
MAX_BLOCK_SIZE = MIN_BLOCK_SIZE << (NUM_BLOCK_SIZES - 1)

#: 32-bit FNV-1 offset basis for the block hash.
FNV_OFFSET_BASIS = 2166136261

#: 32-bit FNV-1 prime for the block hash.
FNV_PRIME = 16777619

#: Hard ceiling on imports entering the imphash digest input.
MAX_IMPORTS = 4096

#: Default cap on bytes read for one fuzzy hash.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024

#: Hard ceiling for ``max_bytes`` (mirrors the loader's file-size guard).
MAX_MAX_BYTES = 512 * 1024 * 1024

#: Hard ceiling on warnings kept in one report.
MAX_WARNINGS = 32

#: The upstream engine's minimum block size; only used by the scoring clamp,
#: which exists to protect the sub-192-byte block-size-3 regime this ladder
#: cannot express.
_SSDEEP_MIN_BLOCKSIZE = 3

#: Evidence sources for the three record kinds.
IMPORT_HASH_SOURCE = "triage.import_hash"
FUZZY_HASH_SOURCE = "triage.fuzzy_hash"
REPORT_SOURCE = "triage.report"

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_SIGNATURE_RE = re.compile(r"^([1-9]\d*):([A-Za-z0-9+/]{0,64}):([A-Za-z0-9+/]{0,64})$")

#: Loader-synthesised names for ordinal imports (``ordinal_7``); the Mandiant
#: convention hashes names, so these are skipped and counted honestly.
_ORDINAL_NAME_RE = re.compile(r"^ordinal_\d+$")


# ---- records -----------------------------------------------------------------


@dataclass(frozen=True)
class ImportHashResult:
    """The Mandiant-convention imphash of one PE file.

    Attributes:
        imphash: MD5 hex digest of the comma-joined lowercase ``dll.function``
            list, in import-table order.
        digest_input: The exact bounded string that was hashed.
        import_count: Number of ``dll.function`` entries in ``digest_input``.
        skipped_unnamed: Imports skipped because they carry no true name
            (loader-synthesised ordinals, imports without a library pairing).
        truncated: True when named imports beyond :data:`MAX_IMPORTS` existed
            but were left out of the digest.
        evidence: Justification record for the digest.
    """

    imphash: str
    digest_input: str
    import_count: int
    skipped_unnamed: int
    truncated: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "imphash": self.imphash,
            "digest_input": self.digest_input,
            "import_count": self.import_count,
            "skipped_unnamed": self.skipped_unnamed,
            "truncated": self.truncated,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class FuzzyHashResult:
    """The ssdeep-style piecewise signature of one file.

    Attributes:
        signature: ``block_size:part1:part2``; part2 is computed at double the
            block size.
        block_size: The block size the engine settled on.
        file_size: Size of the file on disk in bytes.
        hashed_bytes: Bytes actually hashed (``min(file_size, max_bytes)``).
        truncated: True when ``file_size`` exceeded ``max_bytes``; the
            signature then covers only the first ``max_bytes`` bytes.
        evidence: Justification record for the signature.
        warnings: Bounded warnings (at most :data:`MAX_WARNINGS`).
    """

    signature: str
    block_size: int
    file_size: int
    hashed_bytes: int
    truncated: bool
    evidence: Evidence
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "signature": self.signature,
            "block_size": self.block_size,
            "file_size": self.file_size,
            "hashed_bytes": self.hashed_bytes,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }
        return data


@dataclass(frozen=True)
class FuzzyComparison:
    """A 0-100 similarity judgement between two fuzzy signatures.

    Attributes:
        score: ssdeep edit-distance score; identical signature strings score
            100, signatures whose block sizes are neither equal nor a factor
            of two apart score 0.
        same_file: True only when the two signature strings are identical --
            a high score alone is a heuristic judgement and can round up to
            100 for near-identical inputs, which is not proof of identity.
        evidence: Medium-confidence justification (similarity is a heuristic).
    """

    score: int
    same_file: bool
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "same_file": self.same_file,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class TriageHashReport:
    """Every triage hash this engine produces, for one file."""

    path: str
    sha256: str
    size: int
    format: str
    architecture: str
    imphash: ImportHashResult | None
    fuzzy: FuzzyHashResult
    evidence: Evidence
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "format": self.format,
            "architecture": self.architecture,
            "imphash": self.imphash.to_dict() if self.imphash else None,
            "fuzzy": self.fuzzy.to_dict(),
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


# ---- fuzzy hashing -----------------------------------------------------------


def block_size_for_length(length: int) -> int:
    """Initial block-size guess for an input of ``length`` bytes.

    The ssdeep rule: starting at :data:`MIN_BLOCK_SIZE`, double while
    ``block_size * SPAMSUM_LENGTH < length``. This engine stops doubling at
    :data:`MAX_BLOCK_SIZE` so the ladder stays bounded.
    """
    if length < 0:
        raise AnalysisError(f"length must be >= 0, got {length}")
    block_size = MIN_BLOCK_SIZE
    while block_size * SPAMSUM_LENGTH < length and block_size < MAX_BLOCK_SIZE:
        block_size *= 2
    return block_size


def _engine(data: bytes, block_size: int) -> tuple[str, str, int]:
    """One classic ssdeep pass: part1 at ``block_size``, part2 at double.

    Returns ``(part1, part2, part1_length)`` where ``part1_length`` is the
    trigger count before the optional tail character, exactly the ``j`` the
    upstream block-size halving loop tests against ``SPAMSUM_LENGTH / 2``.
    """
    window = [0] * ROLLING_WINDOW
    index = 0
    rh1 = 0
    rh2 = 0
    rh3 = 0
    roll_sum = 0
    block_hash = FNV_OFFSET_BASIS
    half_hash = FNV_OFFSET_BASIS
    part1: list[str] = []
    part2: list[str] = []
    j = 0
    k = 0
    block_mask = block_size - 1
    half_mask = block_size * 2 - 1
    for byte in data:
        leaving = window[index]
        rh2 += ROLLING_WINDOW * byte - rh1
        rh1 += byte - leaving
        window[index] = byte
        index = 0 if index == ROLLING_WINDOW - 1 else index + 1
        rh3 = ((rh3 << 5) & 0xFFFFFFFF) ^ byte
        roll_sum = (rh1 + rh2 + rh3) & 0xFFFFFFFF
        block_hash = ((block_hash * FNV_PRIME) & 0xFFFFFFFF) ^ byte
        half_hash = ((half_hash * FNV_PRIME) & 0xFFFFFFFF) ^ byte
        if roll_sum & block_mask == block_mask:
            char = _B64[block_hash % 64]
            if j < SPAMSUM_LENGTH:
                if j < len(part1):
                    part1[j] = char
                else:
                    part1.append(char)
            if j < SPAMSUM_LENGTH - 1:
                block_hash = FNV_OFFSET_BASIS
                j += 1
        if roll_sum & half_mask == half_mask:
            char = _B64[half_hash % 64]
            if k < SPAMSUM_LENGTH // 2:
                if k < len(part2):
                    part2[k] = char
                else:
                    part2.append(char)
            if k < SPAMSUM_LENGTH // 2 - 1:
                half_hash = FNV_OFFSET_BASIS
                k += 1
    if roll_sum != 0:
        char = _B64[block_hash % 64]
        if j < len(part1):
            part1[j] = char
        else:
            part1.append(char)
        char = _B64[half_hash % 64]
        if k < len(part2):
            part2[k] = char
        else:
            part2.append(char)
    return "".join(part1), "".join(part2), j


def fuzzy_hash_bytes(data: bytes) -> str:
    """Pure ssdeep-style fuzzy hash of ``data``; returns the signature string.

    The initial block size follows the length rule (see
    :func:`block_size_for_length`) and is then halved while the first half
    came out shorter than ``SPAMSUM_LENGTH / 2`` characters, the classic
    ssdeep adjustment.

    Raises:
        AnalysisError: ``data`` is empty (a signature with no content would
            carry no evidence and could never be compared honestly).
    """
    if not data:
        raise AnalysisError("cannot fuzzy-hash empty input: a signature needs at least one byte")
    block_size = block_size_for_length(len(data))
    while True:
        part1, part2, j = _engine(data, block_size)
        if block_size > MIN_BLOCK_SIZE and j < SPAMSUM_LENGTH // 2:
            block_size //= 2
            continue
        break
    return f"{block_size}:{part1}:{part2}"


def fuzzy_hash_file(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> FuzzyHashResult:
    """Fuzzy-hash ``path`` with a byte budget.

    Args:
        path: File to hash.
        max_bytes: Ceiling on bytes read (1 .. :data:`MAX_MAX_BYTES`); a file
            above the cap is still hashed over its first ``max_bytes`` bytes
            with ``truncated`` set and a warning recorded.

    Raises:
        AnalysisError: ``path`` is missing, is not a regular file, is empty,
            unreadable, or ``max_bytes`` is out of range.
    """
    if not 1 <= max_bytes <= MAX_MAX_BYTES:
        raise AnalysisError(f"max_bytes must be between 1 and {MAX_MAX_BYTES}")
    file_path = Path(path)
    try:
        status = os.stat(file_path)
    except OSError as exc:
        raise AnalysisError(f"cannot stat {file_path}: {exc}") from exc
    if not stat_module.S_ISREG(status.st_mode):
        raise AnalysisError(f"not a regular file: {file_path}")
    file_size = status.st_size
    if file_size == 0:
        raise AnalysisError(f"cannot fuzzy-hash empty file: {file_path}")
    hashed_bytes = min(file_size, max_bytes)
    try:
        with open(file_path, "rb") as handle:
            data = handle.read(hashed_bytes)
    except OSError as exc:
        raise AnalysisError(f"cannot read {file_path}: {exc}") from exc
    signature = fuzzy_hash_bytes(data)
    block_size = int(signature.split(":", 1)[0])
    truncated = file_size > hashed_bytes
    warnings: tuple[str, ...] = ()
    if truncated:
        warnings = (
            f"file is {file_size} bytes; the signature covers only the first "
            f"{hashed_bytes} bytes (max_bytes cap)",
        )
    detail = (
        f"ssdeep-style signature derived from {hashed_bytes} bytes read from the file"
        if not truncated
        else f"ssdeep-style signature derived from the first {hashed_bytes} of {file_size} bytes"
    )
    evidence = Evidence(
        source=FUZZY_HASH_SOURCE,
        method="ssdeep_piecewise",
        confidence=Confidence.CERTAIN,
        detail=detail,
        extra={"block_size": block_size, "hashed_bytes": hashed_bytes, "truncated": truncated},
    )
    return FuzzyHashResult(
        signature=signature,
        block_size=block_size,
        file_size=file_size,
        hashed_bytes=hashed_bytes,
        truncated=truncated,
        evidence=evidence,
        warnings=warnings,
    )


# ---- fuzzy comparison --------------------------------------------------------


def _parse_signature(signature: str, argument_name: str) -> tuple[int, str, str]:
    """Split ``block_size:part1:part2`` or raise naming ``argument_name``."""
    match = _SIGNATURE_RE.match(signature)
    if match is None:
        raise AnalysisError(
            f"{argument_name} is not a valid ssdeep signature: {signature!r} "
            "(expected '<block_size>:<hash1>:<hash2>' over the base64 alphabet)"
        )
    return int(match.group(1)), match.group(2), match.group(3)


def _eliminate_sequences(text: str) -> str:
    """Cap runs of identical characters at three (ssdeep compare-time rule)."""
    if len(text) < 4:
        return text
    kept = list(text[:3])
    for position in range(3, len(text)):
        char = text[position]
        if char != text[position - 1] or char != text[position - 2] or char != text[position - 3]:
            kept.append(char)
    return "".join(kept)


def _share_window_substring(first: str, second: str) -> bool:
    """True when both strings share a substring of :data:`ROLLING_WINDOW` chars."""
    if len(first) < ROLLING_WINDOW or len(second) < ROLLING_WINDOW:
        return False
    windows = {first[i : i + ROLLING_WINDOW] for i in range(len(first) - ROLLING_WINDOW + 1)}
    return any(
        second[j : j + ROLLING_WINDOW] in windows
        for j in range(len(second) - ROLLING_WINDOW + 1)
    )


def _edit_distance(first: str, second: str) -> int:
    """Unit-cost Levenshtein distance (what ssdeep's edit_distn computes)."""
    if first == second:
        return 0
    previous = list(range(len(second) + 1))
    for i, first_char in enumerate(first, 1):
        current = [i]
        for j, second_char in enumerate(second, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (0 if first_char == second_char else 1),
                )
            )
        previous = current
    return previous[-1]


def _score_strings(first: str, second: str, block_size: int) -> int:
    """Port of ssdeep's score_strings: edit distance scaled to 0-100."""
    len1, len2 = len(first), len(second)
    if len1 > SPAMSUM_LENGTH or len2 > SPAMSUM_LENGTH:
        return 0
    if not _share_window_substring(first, second):
        return 0
    distance = _edit_distance(first, second)
    score = (distance * SPAMSUM_LENGTH) // (len1 + len2)
    score = (100 * score) // SPAMSUM_LENGTH
    if score >= 100:
        return 0
    score = 100 - score
    limit = (block_size // _SSDEEP_MIN_BLOCKSIZE) * min(len1, len2)
    if score > limit:
        score = limit
    return score


def fuzzy_compare(signature_a: str, signature_b: str) -> FuzzyComparison:
    """Score two ssdeep-style signatures 0-100 (ssdeep's ``fuzzy_compare``).

    Signatures whose block sizes are equal are scored on both halves (best
    score wins); block sizes a factor of two apart are scored on the two
    halves that share a size; anything else scores 0 -- comparable inputs,
    not an error. Identical signature strings score 100.

    Raises:
        AnalysisError: Either argument is not a valid signature; the error
            names which argument (``signature_a`` / ``signature_b``).
    """
    block_size_a, hash_a1, hash_a2 = _parse_signature(signature_a, "signature_a")
    block_size_b, hash_b1, hash_b2 = _parse_signature(signature_b, "signature_b")
    if signature_a == signature_b:
        score = 100
        mode = "identical"
    elif block_size_a != block_size_b and block_size_a != 2 * block_size_b \
            and block_size_b != 2 * block_size_a:
        score = 0
        mode = "incomparable_block_sizes"
    else:
        first_parts = _eliminate_sequences(f"{hash_a1}:{hash_a2}").split(":", 1)
        second_parts = _eliminate_sequences(f"{hash_b1}:{hash_b2}").split(":", 1)
        if block_size_a == block_size_b:
            score = max(
                _score_strings(first_parts[0], second_parts[0], block_size_a),
                _score_strings(first_parts[1], second_parts[1], block_size_b),
            )
            mode = "equal_block_size"
        elif block_size_a == 2 * block_size_b:
            score = _score_strings(first_parts[0], second_parts[1], block_size_a)
            mode = "block_size_double"
        else:
            score = _score_strings(first_parts[1], second_parts[0], block_size_b)
            mode = "block_size_half"
    evidence = Evidence(
        source=FUZZY_HASH_SOURCE,
        method="ssdeep_edit_distance",
        confidence=Confidence.MEDIUM,
        detail="similarity is a heuristic judgement, not an identification",
        extra={
            "block_size_a": block_size_a,
            "block_size_b": block_size_b,
            "mode": mode,
        },
    )
    return FuzzyComparison(
        score=score,
        same_file=score == 100 and mode == "identical",
        evidence=evidence,
    )


# ---- import hashing ----------------------------------------------------------


def _load_info(path: Path) -> BinaryInfo:
    """Load ``path`` through the production loader, typing failures."""
    try:
        return BinaryLoader().load(path)
    except BinaryLoadError as exc:
        raise AnalysisError(f"cannot load {path}: {exc}") from exc


def _import_hash_from_info(info: BinaryInfo) -> ImportHashResult:
    """imphash of an already-loaded binary (the Mandiant convention)."""
    if info.format != "PE":
        raise AnalysisError(
            f"import_hash requires a PE import table: {info.path} is {info.format}. "
            "ELF imports are dynamic symbols without a library pairing in this "
            "loader, and ELF/Mach-O imphash variants are deliberately unsupported "
            "to keep VirusTotal interop honest"
        )
    entries: list[str] = []
    skipped_unnamed = 0
    truncated = False
    for imported in info.imports:
        if imported.library is None or _ORDINAL_NAME_RE.match(imported.name):
            skipped_unnamed += 1
            continue
        if len(entries) >= MAX_IMPORTS:
            truncated = True
            break
        entries.append(f"{imported.library.lower()}.{imported.name.lower()}")
    if not entries:
        raise AnalysisError(
            f"PE has no named imports to hash: {info.path} "
            "(import table empty, ordinal-only, or without library pairing)"
        )
    digest_input = ",".join(entries)
    imphash = hashlib.md5(digest_input.encode("utf-8")).hexdigest()
    evidence = Evidence(
        source=IMPORT_HASH_SOURCE,
        method="mandiant_convention",
        confidence=Confidence.CERTAIN,
        detail="MD5 over the lowercase dll.function list in import-table order",
        extra={
            "imports": len(entries),
            "skipped_unnamed": skipped_unnamed,
            "truncated": truncated,
        },
    )
    return ImportHashResult(
        imphash=imphash,
        digest_input=digest_input,
        import_count=len(entries),
        skipped_unnamed=skipped_unnamed,
        truncated=truncated,
        evidence=evidence,
    )


def import_hash(path: Path) -> ImportHashResult:
    """Compute the Mandiant-convention imphash of the PE at ``path``.

    The digest input is the ordered, comma-joined, lowercase ``dll.function``
    list (bounded to the first :data:`MAX_IMPORTS` named imports). Ordinal
    imports, which this loader renames ``ordinal_N``, have no true name and
    are skipped and counted in ``skipped_unnamed``.

    Raises:
        AnalysisError: ``path`` cannot be loaded, is not a PE, or is a PE
            with no named imports.
    """
    return _import_hash_from_info(_load_info(Path(path)))


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


# ---- composite report --------------------------------------------------------


def triage_hashes(path: Path) -> TriageHashReport:
    """Every triage hash for one file: sha256/format, imphash, fuzzy hash.

    The binary is loaded once; imphash failures (non-PE target, no named
    imports) degrade to ``imphash=None`` plus a warning instead of failing
    the whole report. Fuzzy hashing always runs over the raw file bytes.

    Raises:
        AnalysisError: ``path`` cannot be loaded as a supported binary.
    """
    file_path = Path(path)
    info = _load_info(file_path)
    warnings: list[str] = list(info.warnings)
    try:
        imphash = _import_hash_from_info(info)
    except AnalysisError as exc:
        imphash = None
        _warn(warnings, f"no imphash: {exc}")
    fuzzy = fuzzy_hash_file(file_path)
    for warning in fuzzy.warnings:
        _warn(warnings, warning)
    evidence = Evidence(
        source=REPORT_SOURCE,
        method="composite",
        confidence=Confidence.CERTAIN,
        detail=(
            "sha256, size and format from the loader; imphash and the fuzzy "
            "signature derived from bytes read from the file"
        ),
        extra={"format": info.format, "architecture": info.architecture},
    )
    return TriageHashReport(
        path=str(info.path),
        sha256=info.sha256,
        size=info.file_size,
        format=info.format,
        architecture=info.architecture,
        imphash=imphash,
        fuzzy=fuzzy,
        evidence=evidence,
        warnings=tuple(warnings),
    )

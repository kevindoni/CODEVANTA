"""Self-contained, tamper-evident evidence bundles for one analysis subject.

An analysis result is only useful to somebody else if that somebody can check
it.  A bundle therefore pins the *input* and every *output* in one JSON
document:

* ``manifest.subject`` / ``manifest.subject_sha256`` identify the binary that
  was analysed and its SHA-256 digest, so a verifier can re-hash the file and
  confirm they are looking at the same bytes.
* ``entries`` holds one record per analysis payload (``cfg``, ``callgraph``,
  ``strings``, ...) with the payload inlined next to its own digest and size.
* ``manifest.entries_sha256`` is a single digest over the whole entry table, so
  adding, removing or renaming an entry -- or editing one entry's recorded
  digest, size or media type -- is detectable as one mismatch.

Canonical form
--------------

Every payload is reduced to *canonical JSON* before it is hashed:

.. code-block:: python

    json.dumps(payload, sort_keys=True, separators=(",", ":"),
               ensure_ascii=True, allow_nan=False)

The result is a byte string that does not depend on the producer's key
insertion order, indentation or locale, which is what makes

.. code-block:: python

    hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

reproducible by a third party who only has the bundle.  ``allow_nan=False``
means ``NaN``/``Infinity`` are rejected rather than written as Python-only
tokens, so the document stays parseable by strict JSON readers.

The entry-table digest is the SHA-256 of canonical JSON of a list of
``[name, sha256, bytes, media_type]`` rows sorted by ``name``::

    [[name, sha256_hex, payload_bytes, media_type], ...]

so it can be recomputed in any language, not just Python
(:func:`entries_digest` exposes the same recipe).

What a bundle does and does not prove
-------------------------------------

It proves **integrity**: :func:`verify_bundle` recomputes every payload digest
and the entry-table digest, so any edit -- one flipped character inside a
payload, an edited ``sha256``, an edited ``entries_sha256``, a dropped entry --
is reported with the entry name and the expected/actual values.  Two builds
from the same inputs serialise to identical bytes apart from ``created_at``.

It does **not** prove **authenticity**: there is no signature and no secret, so
anybody who can rewrite the whole document can also recompute every digest.
``subject`` is a caller-supplied label and is *not* trusted input; only
``subject_sha256`` binds the bundle to real bytes.  Treat a bundle as evidence
about a file, not as a statement about who produced it.

Bounds and failure modes
------------------------

* at most :data:`MAX_ENTRIES` (256) entries;
* at most :data:`MAX_PAYLOAD_BYTES` (16 MiB) of canonical JSON per payload;
* the subject must exist and be a readable regular file;
* payloads that are not JSON-serialisable are rejected.

Every rejection raises :class:`~codevanta.core.report.AnalysisError`; a bundle
is never written partially.  Only the standard library is used.

Reading a bundle back
---------------------

The file written by :func:`write_bundle` is exactly :meth:`Bundle.to_dict`
serialised with ``sort_keys=True``, ``indent=2`` and ``ensure_ascii=True``, so
it diffs and reviews well.  :func:`read_bundle` rejects a structurally broken
document (missing payload, malformed digest) with
:class:`AnalysisError`; for forensic checks on a possibly damaged file, parse
the JSON and hand the mapping to :func:`verify_bundle`, which reports damage
instead of raising.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from codevanta.core.report import AnalysisError
from codevanta.core.unknowns import UNKNOWN_ENTRY_NAME, UnknownRecord, records_to_payload

__all__ = [
    "DEFAULT_ALGORITHM",
    "MAX_ENTRIES",
    "MAX_PAYLOAD_BYTES",
    "MEDIA_TYPE_JSON",
    "SUBJECT_CHUNK_BYTES",
    "SUPPORTED_ALGORITHMS",
    "TOOL_VERSION",
    "UNKNOWN_ENTRY_NAME",
    "Bundle",
    "BundleManifest",
    "BundleVerification",
    "build_bundle",
    "canonical_json",
    "dumps_bundle",
    "entries_digest",
    "hash_subject",
    "read_bundle",
    "verify_bundle",
    "write_bundle",
]

#: Digest recorded in :attr:`BundleManifest.algorithm` and used everywhere here.
DEFAULT_ALGORITHM = "sha256"

#: Algorithms :func:`verify_bundle` can recompute.  Anything else is a problem,
#: never a silent pass.
SUPPORTED_ALGORITHMS = frozenset({DEFAULT_ALGORITHM})

#: Version string stamped into every manifest.  Mirrors
#: :data:`codevanta.mcp_server.server.SERVER_VERSION`.
TOOL_VERSION = "0.1.0"

#: Media type recorded for a canonically serialised JSON payload.
MEDIA_TYPE_JSON = "application/json"

#: Hard ceiling on entries in one bundle (bounded work for the verifier).
MAX_ENTRIES = 256

#: Hard ceiling on one payload's canonical JSON, in bytes.
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024

#: Read size used when hashing the subject binary: the file is streamed, never
#: loaded whole.
SUBJECT_CHUNK_BYTES = 1024 * 1024

#: Shape of a SHA-256 hex digest as stored in a bundle.
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

#: Manifest keys that must be non-blank strings.
_MANIFEST_TEXT_KEYS = (
    "created_at",
    "tool_version",
    "subject",
    "subject_sha256",
    "entries_sha256",
)


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 hex digest of ``data``."""
    return hashlib.new(DEFAULT_ALGORITHM, data).hexdigest()


def canonical_json(payload: Any) -> str:
    """Serialise ``payload`` to the canonical JSON text that gets hashed.

    Key order, indentation, non-ASCII escaping and float formatting are all
    fixed, so equal payloads always produce equal bytes and therefore equal
    digests.

    Args:
        payload: Any JSON-serialisable value.

    Returns:
        The canonical JSON text (always ASCII, no newlines).

    Raises:
        AnalysisError: When ``payload`` is not JSON-serialisable or contains a
            ``NaN``/``Infinity`` value.
    """
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"payload is not canonical JSON: {exc}") from exc


def entries_digest(entries: Mapping[str, Mapping[str, Any]]) -> str:
    """Return the combined digest over an entry table.

    The recipe is the SHA-256 of canonical JSON of
    ``[[name, sha256, bytes, media_type], ...]`` sorted by ``name``; it is
    documented in the module docstring so non-Python verifiers can reproduce
    it.

    Args:
        entries: Mapping of entry name to a record carrying ``sha256``,
            ``bytes`` and ``media_type``.

    Returns:
        The lowercase hex digest of the whole table.

    Raises:
        AnalysisError: When a record is missing or carries malformed metadata.
    """
    table: list[list[Any]] = []
    for name in sorted(entries):
        record = entries[name]
        digest = record.get("sha256")
        size = record.get("bytes")
        media_type = record.get("media_type")
        if not isinstance(digest, str) or not isinstance(size, int) or isinstance(size, bool):
            raise AnalysisError(f"entry {name!r} has malformed digest metadata")
        if not isinstance(media_type, str):
            raise AnalysisError(f"entry {name!r} has a malformed media_type")
        table.append([name, digest, size, media_type])
    return _sha256_hex(canonical_json(table).encode("utf-8"))


def hash_subject(subject_path: str | Path) -> str:
    """Stream ``subject_path`` through SHA-256 and return the hex digest.

    The file is read in :data:`SUBJECT_CHUNK_BYTES` chunks, so hashing a large
    binary never loads it into memory.

    Args:
        subject_path: Path to the analysed binary.

    Returns:
        The lowercase hex digest of the file's bytes.

    Raises:
        AnalysisError: When the path does not exist, is not a regular file or
            cannot be read.
    """
    target = Path(subject_path)
    try:
        exists = target.exists()
        is_file = target.is_file()
    except OSError as exc:  # pragma: no cover - exotic filesystem errors only
        raise AnalysisError(f"cannot inspect subject binary {target}: {exc}") from exc
    if not exists:
        raise AnalysisError(f"subject binary not found: {target}")
    if not is_file:
        raise AnalysisError(f"subject binary is not a regular file: {target}")

    digest = hashlib.new(DEFAULT_ALGORITHM)
    try:
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(SUBJECT_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AnalysisError(f"cannot read subject binary {target}: {exc}") from exc
    return digest.hexdigest()



@dataclass(frozen=True)
class BundleManifest:
    """What a bundle covers: the subject, its digest and the entry-table digest.

    Attributes:
        created_at: ISO-8601 UTC timestamp of the build.
        tool_version: CODEVANTA version that produced the bundle.
        subject: Human-readable label for the analysed binary -- the file name by
            default, or the caller's ``label``.  Never trusted input.
        subject_sha256: Digest of the analysed bytes; this is what binds the
            bundle to a real file.
        entry_count: Number of entries in the bundle.
        entries_sha256: Combined digest over the whole entry table.
        algorithm: Digest algorithm name.  Only ``"sha256"`` is supported.
    """

    created_at: str
    tool_version: str
    subject: str
    subject_sha256: str
    entry_count: int
    entries_sha256: str
    algorithm: str = DEFAULT_ALGORITHM

    def to_dict(self) -> dict[str, Any]:
        """Serialise the manifest as a JSON-safe dict."""
        return {
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "entries_sha256": self.entries_sha256,
            "entry_count": self.entry_count,
            "subject": self.subject,
            "subject_sha256": self.subject_sha256,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True)
class Bundle:
    """A subject digest plus the hashed payloads that describe it.

    Attributes:
        manifest: The bundle's :class:`BundleManifest`.
        entries: Read-only mapping of entry name to ``{"sha256", "bytes",
            "media_type"}``, sorted by name.  The payload itself is not part of
            this mapping; use :meth:`payload`.

    Instances are frozen and the mappings are :class:`types.MappingProxyType`,
    so a built bundle cannot be mutated behind the verifier's back.
    """

    manifest: BundleManifest
    entries: Mapping[str, Mapping[str, Any]]
    _payload_texts: Mapping[str, str] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        records = {
            name: MappingProxyType(dict(self.entries[name])) for name in sorted(self.entries)
        }
        object.__setattr__(self, "entries", MappingProxyType(records))
        object.__setattr__(self, "_payload_texts", MappingProxyType(dict(self._payload_texts)))

    @property
    def names(self) -> tuple[str, ...]:
        """Entry names in the deterministic (sorted) order."""
        return tuple(sorted(self.entries))

    def payload(self, name: str) -> Any:
        """Return the payload stored under ``name``.

        The value is decoded from the exact canonical text that was hashed, so
        the returned object always reproduces the recorded digest.

        Raises:
            AnalysisError: When the bundle has no such entry.
        """
        text = self._payload_texts.get(name)
        if text is None:
            raise AnalysisError(f"bundle has no entry {name!r}")
        return json.loads(text)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the bundle, inlining every payload next to its digest.

        The returned dict is JSON-safe and is exactly what
        :func:`write_bundle` persists.
        """
        entries: dict[str, dict[str, Any]] = {}
        for name in self.names:
            record = dict(self.entries[name])
            record["payload"] = self.payload(name)
            entries[name] = record
        return {"manifest": self.manifest.to_dict(), "entries": entries}


@dataclass(frozen=True)
class BundleVerification:
    """Outcome of :func:`verify_bundle`.

    Attributes:
        passed: ``True`` only when no problem was found.
        problems: Human-readable findings, each naming the entry or manifest
            field that failed and the expected/actual values.
        manifest: The manifest that was checked; fields that could not be parsed
            are reported as empty/zero rather than raised.
    """

    passed: bool
    problems: tuple[str, ...]
    manifest: BundleManifest

    def to_dict(self) -> dict[str, Any]:
        """Serialise the verification outcome as a JSON-safe dict."""
        return {
            "passed": self.passed,
            "problems": list(self.problems),
            "manifest": self.manifest.to_dict(),
        }


@dataclass(frozen=True)
class _ParsedDocument:
    """Structural view of a bundle document, with damage recorded in problems."""

    manifest: BundleManifest
    entries: dict[str, dict[str, Any]]
    payloads: dict[str, str]
    names: tuple[str, ...]
    problems: tuple[str, ...]



def _entry_metadata(
    name: str, record: Mapping[str, Any], problems: list[str]
) -> dict[str, Any] | None:
    """Extract ``{"sha256", "bytes", "media_type"}``, or report why not."""
    digest = record.get("sha256")
    if not isinstance(digest, str) or _SHA256_HEX.fullmatch(digest) is None:
        problems.append(f"entry {name!r}: sha256 is missing or malformed ({digest!r})")
        return None
    size = record.get("bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        problems.append(f"entry {name!r}: byte length is missing or malformed ({size!r})")
        return None
    media_type = record.get("media_type")
    if not isinstance(media_type, str) or not media_type:
        problems.append(f"entry {name!r}: media_type is missing or malformed ({media_type!r})")
        return None
    return {"sha256": digest, "bytes": size, "media_type": media_type}


def _parse_manifest(raw: Any, problems: list[str]) -> BundleManifest:
    """Parse a manifest, recording damage instead of raising."""
    if not isinstance(raw, Mapping):
        problems.append("manifest: missing or not a JSON object")
        return BundleManifest(
            created_at="",
            tool_version="",
            subject="",
            subject_sha256="",
            entry_count=0,
            entries_sha256="",
        )

    fields: dict[str, str] = {}
    for key in _MANIFEST_TEXT_KEYS:
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            problems.append(f"manifest: {key} is missing or not a non-empty string")
            value = ""
        fields[key] = value
    for key in ("subject_sha256", "entries_sha256"):
        if fields[key] and _SHA256_HEX.fullmatch(fields[key]) is None:
            problems.append(f"manifest: {key} is not a 64-character lowercase hex digest")

    count = raw.get("entry_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        problems.append(f"manifest: entry_count is missing or malformed ({count!r})")
        count = 0

    algorithm = raw.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm:
        problems.append(f"manifest: algorithm is missing or malformed ({algorithm!r})")
        algorithm = DEFAULT_ALGORITHM
    elif algorithm not in SUPPORTED_ALGORITHMS:
        problems.append(f"manifest: unsupported algorithm {algorithm!r}")

    return BundleManifest(
        created_at=fields["created_at"],
        tool_version=fields["tool_version"],
        subject=fields["subject"],
        subject_sha256=fields["subject_sha256"],
        entry_count=count,
        entries_sha256=fields["entries_sha256"],
        algorithm=algorithm,
    )


def _parse_document(document: Mapping[str, Any]) -> _ParsedDocument:
    """Parse a bundle document into metadata, canonical payloads and problems."""
    problems: list[str] = []
    manifest = _parse_manifest(document.get("manifest"), problems)

    raw_entries = document.get("entries")
    if not isinstance(raw_entries, Mapping):
        problems.append("bundle: entries is missing or not a JSON object")
        raw_entries = {}

    names: list[str] = []
    entries: dict[str, dict[str, Any]] = {}
    payloads: dict[str, str] = {}
    for name in sorted(raw_entries, key=str):
        if not isinstance(name, str) or not name.strip():
            problems.append(f"entry {name!r}: name must be a non-empty string")
            continue
        names.append(name)
        record = raw_entries[name]
        if not isinstance(record, Mapping):
            problems.append(f"entry {name!r}: record is not a JSON object")
            continue
        metadata = _entry_metadata(name, record, problems)
        if metadata is None:
            continue
        entries[name] = metadata
        if "payload" not in record:
            problems.append(f"entry {name!r}: payload is missing")
            continue
        try:
            payloads[name] = canonical_json(record["payload"])
        except AnalysisError as exc:
            problems.append(f"entry {name!r}: {exc}")

    return _ParsedDocument(
        manifest=manifest,
        entries=entries,
        payloads=payloads,
        names=tuple(names),
        problems=tuple(problems),
    )




def build_bundle(
    subject_path: str | Path,
    payloads: Mapping[str, Any],
    *,
    label: str | None = None,
    unknowns: Sequence[UnknownRecord] | None = None,
) -> Bundle:
    """Hash a binary and a set of analysis payloads into one bundle.

    Entries are sorted by name, so two builds from the same inputs serialise to
    identical bytes regardless of the ``payloads`` insertion order.

    Args:
        subject_path: The analysed binary; it must exist and be readable.
        payloads: Mapping of entry name to any JSON-serialisable payload.
        label: Optional subject label.  Defaults to the binary's file name.
        unknowns: Optional residual-unknown records; when given (even empty
            non-``None``), they are serialised through
            :func:`codevanta.core.unknowns.records_to_payload` and embedded as
            one extra entry named :data:`UNKNOWN_ENTRY_NAME`, hashed like any
            other payload. Pass ``None`` to omit the section.

    Returns:
        The populated :class:`Bundle`.

    Raises:
        AnalysisError: When the subject is missing/unreadable, when ``payloads``
            is not a mapping, when a name is blank, when ``payloads`` already
            reserves the ``unknowns`` entry while ``unknowns`` is given, when
            there are more than :data:`MAX_ENTRIES` entries, or when a payload
            is not JSON-serialisable or exceeds :data:`MAX_PAYLOAD_BYTES`.
    """
    subject_sha256 = hash_subject(subject_path)

    if not isinstance(payloads, Mapping):
        raise AnalysisError(f"payloads must be a mapping, got {type(payloads).__name__}")
    if UNKNOWN_ENTRY_NAME in payloads and unknowns is not None:
        raise AnalysisError(
            f"payloads already contain an {UNKNOWN_ENTRY_NAME!r} entry; pass it in "
            "payloads or as unknowns records, not both"
        )
    merged: dict[str, Any] = dict(payloads)
    if unknowns is not None:
        merged[UNKNOWN_ENTRY_NAME] = records_to_payload(list(unknowns))
    if len(merged) > MAX_ENTRIES:
        raise AnalysisError(f"too many entries ({len(merged)} > limit {MAX_ENTRIES})")

    subject = label if label is not None else Path(subject_path).name
    if not isinstance(subject, str) or not subject.strip():
        raise AnalysisError(f"subject label must be a non-empty string, got {subject!r}")

    entries: dict[str, dict[str, Any]] = {}
    payload_texts: dict[str, str] = {}
    for name in sorted(merged, key=str):
        if not isinstance(name, str) or not name.strip():
            raise AnalysisError(f"entry name must be a non-empty string, got {name!r}")
        text = canonical_json(merged[name])
        data = text.encode("utf-8")
        if len(data) > MAX_PAYLOAD_BYTES:
            raise AnalysisError(
                f"payload {name!r} is too large ({len(data)} bytes > limit {MAX_PAYLOAD_BYTES})"
            )
        payload_texts[name] = text
        entries[name] = {
            "sha256": _sha256_hex(data),
            "bytes": len(data),
            "media_type": MEDIA_TYPE_JSON,
        }

    manifest = BundleManifest(
        created_at=_utc_now_iso(),
        tool_version=TOOL_VERSION,
        subject=subject,
        subject_sha256=subject_sha256,
        entry_count=len(entries),
        entries_sha256=entries_digest(entries),
    )
    return Bundle(manifest=manifest, entries=entries, _payload_texts=payload_texts)

def verify_bundle(
    bundle_or_dict: Bundle | Mapping[str, Any],
    *,
    subject_path: str | Path | None = None,
) -> BundleVerification:
    """Recompute every digest in a bundle and report each mismatch.

    Two independent checks run:

    1. per entry -- the inlined payload is re-canonicalised, re-hashed and
       re-measured, then compared with the recorded ``sha256`` and ``bytes``;
    2. per table -- :func:`entries_digest` over the recorded entry table is
       compared with ``manifest.entries_sha256``, which catches added, removed,
       renamed or re-metadata'ed entries, including an edited ``sha256`` whose
       payload was left alone.

    ``manifest.entry_count`` and ``manifest.algorithm`` are checked too, and
    structurally damaged input is reported as a problem rather than raised.

    Args:
        bundle_or_dict: A :class:`Bundle` or the mapping returned by
            :meth:`Bundle.to_dict` (or parsed from a written file).
        subject_path: Optional path to the analysed binary.  When given, its
            digest is recomputed and compared with ``manifest.subject_sha256``,
            which is the only way to confirm the bundle describes *this* file.

    Returns:
        A :class:`BundleVerification` whose ``problems`` name the failing entry
        and the expected/actual values.

    Raises:
        AnalysisError: When ``bundle_or_dict`` is neither a bundle nor a
            mapping, or when ``subject_path`` cannot be read.
    """
    if isinstance(bundle_or_dict, Bundle):
        document: Mapping[str, Any] = bundle_or_dict.to_dict()
    elif isinstance(bundle_or_dict, Mapping):
        document = bundle_or_dict
    else:
        raise AnalysisError(
            f"bundle must be a Bundle or a mapping, got {type(bundle_or_dict).__name__}"
        )

    parsed = _parse_document(document)
    problems: list[str] = list(parsed.problems)

    for name in sorted(parsed.payloads):
        data = parsed.payloads[name].encode("utf-8")
        recorded = parsed.entries[name]
        actual_digest = _sha256_hex(data)
        if actual_digest != recorded["sha256"]:
            problems.append(
                f"entry {name!r}: payload sha256 mismatch "
                f"(expected {recorded['sha256']}, actual {actual_digest})"
            )
        if len(data) != recorded["bytes"]:
            problems.append(
                f"entry {name!r}: payload size mismatch "
                f"(expected {recorded['bytes']}, actual {len(data)})"
            )

    if parsed.manifest.entry_count != len(parsed.names):
        problems.append(
            f"manifest: entry_count mismatch "
            f"(expected {parsed.manifest.entry_count}, actual {len(parsed.names)})"
        )

    actual_entries = entries_digest(parsed.entries)
    if actual_entries != parsed.manifest.entries_sha256:
        problems.append(
            f"manifest: entries_sha256 mismatch "
            f"(expected {parsed.manifest.entries_sha256}, actual {actual_entries})"
        )

    if subject_path is not None:
        actual_subject = hash_subject(subject_path)
        if actual_subject != parsed.manifest.subject_sha256:
            problems.append(
                f"subject {str(subject_path)!r}: sha256 mismatch "
                f"(expected {parsed.manifest.subject_sha256}, actual {actual_subject})"
            )

    return BundleVerification(
        passed=not problems,
        problems=tuple(problems),
        manifest=parsed.manifest,
    )


def dumps_bundle(bundle: Bundle) -> str:
    """Return the canonical JSON text of ``bundle``, as written to disk.

    Keys are sorted, indentation is two spaces, non-ASCII is escaped and the
    text ends with a single newline, so two bundles with the same content
    serialise to identical bytes.
    """
    return json.dumps(bundle.to_dict(), sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def write_bundle(bundle: Bundle, path: str | Path) -> Path:
    """Write ``bundle`` to ``path`` as canonical JSON.

    Args:
        bundle: The bundle to persist.
        path: Destination file; parent directories must already exist.

    Returns:
        The destination path.

    Raises:
        AnalysisError: When the file cannot be written.
    """
    target = Path(path)
    try:
        target.write_text(dumps_bundle(bundle), encoding="utf-8", newline="\n")
    except OSError as exc:
        raise AnalysisError(f"cannot write bundle {target}: {exc}") from exc
    return target


def _load_document(path: str | Path) -> Mapping[str, Any]:
    """Read and parse a bundle file, raising ``AnalysisError`` on damage."""
    target = Path(path)
    try:
        with target.open(encoding="utf-8") as handle:
            text = handle.read()
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"bundle {target} is not UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise AnalysisError(f"cannot read bundle {target}: {exc}") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"bundle {target} is not valid JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise AnalysisError(f"bundle {target} is not a JSON object")
    return document


def read_bundle(path: str | Path) -> Bundle:
    """Load a bundle previously written by :func:`write_bundle`.

    Structure is checked so the returned bundle is usable; digests are *not*
    checked here -- that is :func:`verify_bundle`'s job, and keeping the two
    separate lets a caller round-trip and then re-verify.

    Args:
        path: Bundle file to read.

    Returns:
        The :class:`Bundle` described by the file.

    Raises:
        AnalysisError: When the file cannot be read, is not JSON, or is
            structurally damaged (missing manifest fields, missing payload,
            malformed digest).
    """
    document = _load_document(path)
    parsed = _parse_document(document)
    if parsed.problems:
        raise AnalysisError(f"invalid bundle {path}: {'; '.join(parsed.problems)}")
    return Bundle(
        manifest=parsed.manifest,
        entries=parsed.entries,
        _payload_texts=parsed.payloads,
    )

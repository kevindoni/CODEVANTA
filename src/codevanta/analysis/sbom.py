"""CycloneDX 1.6 SBOM export over the CODEVANTA inventories (pure stdlib).

Turns what the other lanes have already proved into a Software Bill of
Materials, inspired by `anchore/syft` but implemented with the Python
standard library only (``json``, ``hashlib``, ``uuid``, ``pathlib``):

* **JavaScript applications** (directory or ``.asar`` archive, through
  :func:`~codevanta.analysis.javascript.analyze_javascript_app`) contribute
  one ``library`` component per external package (bare import, reduced to its
  package name) plus one ``application`` component for the app itself. A
  purl ``pkg:npm/<name>@<version>`` is emitted only when ``package.json``
  declares an *exact* version for that package -- ranges such as ``^1.2.3``
  are demands, not facts, and never become versions.
* **Binaries** (PE / ELF / Mach-O / DEX, through
  :class:`~codevanta.core.loader.BinaryLoader`) contribute one ``library``
  component per imported dynamic library named by the import inventory and
  one ``application`` component for the file itself, carrying the SHA-256 of
  its bytes. Versions are never claimed for binaries: the import table does
  not know one.

Guarantees:

* **Deterministic.** The same input set produces a byte-identical document:
  the ``serialNumber`` is a ``uuid5`` over the sorted, deduplicated
  ``(path, sha256)`` pairs (a JavaScript directory is represented by the
  digest of its root ``package.json``, or the empty digest when absent),
  components are sorted by ``(type, name, purl)``, duplicates are merged
  with their sources unioned, and no timestamp is emitted.
* **Honest.** Versions and purls appear only when derivable; every component
  carries a ``codevanta:evidence`` property (``source/method/confidence``,
  one line) and a ``codevanta:sources`` property naming the inputs that
  produced it.
* **Bounded.** ``max_components`` (1..20000, default 2000) keeps the first
  N sorted components and reports the cut through ``truncated``, the honest
  ``component_count`` (kept + cut) and a warning -- never silently.

Known gap: Go build info and cargo-auditable crate lists (detected by
:mod:`codevanta.analysis.binmeta`) are not lifted into components yet.

Malformed input (empty path sequence, a path that cannot be stat'ed, an
input that is neither a directory, an ``.asar`` archive, nor a loadable
binary) raises :class:`~codevanta.core.report.AnalysisError` naming the
path.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import codevanta
from codevanta.analysis.asar import extract_file
from codevanta.analysis.javascript import MAX_FILE_BYTES, analyze_javascript_app
from codevanta.core.loader import BinaryLoadError, ImportInfo
from codevanta.core.report import AnalysisError, load_binary
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_COMPONENTS",
    "EVIDENCE_SOURCE",
    "MAX_COMPONENTS",
    "MAX_WARNINGS",
    "SPEC_VERSION",
    "SbomComponent",
    "SbomReport",
    "build_sbom",
]

#: CycloneDX specification version emitted by this module.
SPEC_VERSION = "1.6"

#: Hard ceiling accepted for ``max_components``.
MAX_COMPONENTS = 20_000

#: Default ceiling on components kept in one document.
DEFAULT_MAX_COMPONENTS = 2000

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Evidence source of the report-level record.
EVIDENCE_SOURCE = "sbom.export"

#: purl prefix for npm packages.
_NPM_PURL_PREFIX = "pkg:npm/"

#: Deterministic UUID namespace for serial numbers ("codevanta").
_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "codevanta")

#: ``package.json`` sections consulted for exact dependency versions (the
#: same sections :mod:`codevanta.analysis.javascript` reads for electron).
_DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")

#: Hashing chunk size (bounded memory for large archives).
_HASH_CHUNK = 1024 * 1024

#: A dependency value is a *known version* only when it is exact: ranges
#: ("^1.2.3", "~2", ">=3", "*", "latest", "workspace:...") are demands, not
#: facts, so only plain dotted numbers with optional pre-release/build
#: suffixes qualify.
_EXACT_VERSION_RE = re.compile(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?")


@dataclass(frozen=True)
class SbomComponent:
    """One CycloneDX component derived from a CODEVANTA inventory.

    Attributes:
        type: ``"application"`` or ``"library"``.
        name: Component name (package name, file stem, or import name).
        evidence: One-line ``source/method/confidence`` justification.
        version: Exact version when known, else ``None`` (field omitted).
        purl: Package URL when derivable, else ``None`` (field omitted).
        sha256: SHA-256 of the component's bytes when it is a hashed file.
        sources: Input paths (``str``) that produced this component; merged
            duplicates union their sources.
    """

    type: str
    name: str
    evidence: str
    version: str | None = None
    purl: str | None = None
    sha256: str | None = None
    sources: tuple[str, ...] = ()

    @property
    def sort_key(self) -> tuple[str, str, str]:
        """Deterministic document order: ``(type, name, purl-or-empty)``."""
        return (self.type, self.name, self.purl or "")

    @property
    def merge_key(self) -> tuple[str, str, str, str]:
        """Identity for deduplication: ``(type, name, version, purl)``."""
        return (self.type, self.name, self.version or "", self.purl or "")

    def to_dict(self) -> dict[str, Any]:
        """The JSON-safe CycloneDX fragment for this component."""
        data: dict[str, Any] = {"type": self.type, "name": self.name}
        if self.version is not None:
            data["version"] = self.version
        if self.purl is not None:
            data["purl"] = self.purl
        if self.sha256 is not None:
            data["hashes"] = [{"alg": "SHA-256", "content": self.sha256}]
        data["properties"] = [
            {"name": "codevanta:evidence", "value": self.evidence},
            {"name": "codevanta:sources", "value": ";".join(sorted(set(self.sources)))},
        ]
        return data


@dataclass(frozen=True)
class SbomReport:
    """The CycloneDX 1.6 document built from one or more CODEVANTA inputs.

    Attributes:
        paths: The input paths, in the order they were given.
        components: The components kept after sorting, merging and the cap.
        component_count: Honest total (kept + cut) before the cap.
        truncated: True when ``max_components`` cut the component list.
        warnings: Bounded, human-readable notes (cap hits, degraded scans).
        evidence: Report-level evidence record (``sbom.export``).
        serial_number: ``urn:uuid:<uuid5>`` over the sorted input digests.
    """

    paths: tuple[Path, ...]
    components: tuple[SbomComponent, ...]
    component_count: int
    truncated: bool
    warnings: tuple[str, ...]
    evidence: Evidence
    serial_number: str

    def to_dict(self) -> dict[str, Any]:
        """The full CycloneDX document as a JSON-safe dict (no timestamp)."""
        tool: dict[str, Any] = {"type": "application", "name": "codevanta"}
        tool_version = getattr(codevanta, "__version__", None)
        if isinstance(tool_version, str):
            tool["version"] = tool_version
        return {
            "bomFormat": "CycloneDX",
            "specVersion": SPEC_VERSION,
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": {"tools": {"components": [tool]}},
            "components": [component.to_dict() for component in self.components],
        }

    def to_json(self) -> str:
        """The document as pretty JSON; document order matters, so keys are
        emitted in insertion order (``sort_keys=False``)."""
        return json.dumps(self.to_dict(), indent=2)


def build_sbom(
    paths: Sequence[Path], *, max_components: int = DEFAULT_MAX_COMPONENTS
) -> SbomReport:
    """Aggregate CODEVANTA inventories into one CycloneDX 1.6 document.

    Args:
        paths: One or more inputs. Each path is a PE/ELF/Mach-O/DEX binary
            file, or a JavaScript application directory / ``.asar`` archive.
        max_components: Ceiling on components kept in the document
            (1..MAX_COMPONENTS); the cut is reported, never silent.

    Returns:
        The :class:`SbomReport`; ``to_dict()`` is the CycloneDX document and
        ``to_json()`` its pretty serialization.

    Raises:
        AnalysisError: ``max_components`` is out of range, ``paths`` is
            empty, a path cannot be stat'ed, or a path is neither a
            directory, an ``.asar`` archive, nor a loadable binary. The
            message names the offending path.
    """
    if not 1 <= max_components <= MAX_COMPONENTS:
        raise AnalysisError(f"max_components must be between 1 and {MAX_COMPONENTS}")
    inputs = tuple(Path(path) for path in paths)
    if not inputs:
        raise AnalysisError("paths must not be empty")
    collected: list[SbomComponent] = []
    warnings: list[str] = []
    pairs: set[tuple[str, str]] = set()
    for path in inputs:
        try:
            path.stat()
        except OSError as exc:
            raise AnalysisError(f"cannot stat {path}: {exc}") from exc
        if path.is_dir():
            components, digest = _js_components(path, is_asar=False, warnings=warnings)
        elif path.suffix.lower() == ".asar" and path.is_file():
            components, digest = _js_components(path, is_asar=True, warnings=warnings)
        elif path.is_file():
            components, digest = _binary_components(path, warnings=warnings)
        else:
            raise AnalysisError(
                f"cannot classify {path}: not a directory, an .asar archive, or a regular file"
            )
        collected.extend(components)
        pairs.add((str(path), digest))
    merged = _merge_components(collected, warnings)
    kept = merged[:max_components]
    truncated = len(merged) > max_components
    if truncated:
        _warn(
            warnings,
            f"component cap {max_components} reached: "
            f"kept {max_components} of {len(merged)} components",
        )
    return SbomReport(
        paths=inputs,
        components=tuple(kept),
        component_count=len(merged),
        truncated=truncated,
        warnings=tuple(warnings),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="inventory_aggregation",
            confidence=Confidence.MEDIUM,
            detail=(
                "aggregates per-lane inventories that are individually certain; "
                "purl and version gaps keep the document medium"
            ),
        ),
        serial_number=_serial_number(pairs),
    )


# ---- JavaScript applications ------------------------------------------------


def _js_components(
    path: Path, *, is_asar: bool, warnings: list[str]
) -> tuple[list[SbomComponent], str]:
    """Derive components and a content digest from one JavaScript app."""
    report = analyze_javascript_app(path)
    for message in report.warnings:
        _warn(warnings, f"javascript {path}: {message}")
    if report.truncated:
        _warn(
            warnings,
            f"javascript scan of {path} was truncated; the inventory may be incomplete",
        )
    manifest_bytes = _manifest_bytes(path, is_asar=is_asar)
    manifest = _parse_manifest(manifest_bytes)
    payload = report.to_dict()
    external: dict[str, Any] = payload["external_packages"]
    versions = _dependency_versions(manifest)
    source = str(path)
    components = [
        SbomComponent(
            type="library",
            name=name,
            evidence=_evidence_line("js.static", "module_scan", Confidence.CERTAIN),
            version=versions.get(name),
            purl=_npm_purl(name, versions.get(name)),
            sources=(source,),
        )
        for name in sorted(external)
    ]
    declared = manifest.get("name") if manifest is not None else None
    if isinstance(declared, str) and declared:
        app_name, from_manifest = declared, True
    else:
        # Directory name for an extracted app, archive stem for an .asar.
        app_name, from_manifest = (path.stem if is_asar else path.name), False
    app_version = _exact_version(manifest.get("version")) if manifest is not None else None
    components.append(
        SbomComponent(
            type="application",
            name=app_name,
            evidence=(
                _evidence_line("js.static", "package_json", Confidence.CERTAIN)
                if from_manifest
                else _evidence_line("js.static", "fallback_name", Confidence.MEDIUM)
            ),
            version=app_version,
            purl=_npm_purl(app_name, app_version) if from_manifest else None,
            sources=(source,),
        )
    )
    # Content digest for the serial number: the archive's own bytes for an
    # .asar (it is one file), the manifest's bytes for a directory (or the
    # empty digest when absent -- the scanned file set is already summarized
    # by the component list itself).
    if is_asar:
        digest = _file_sha256(path)
    else:
        digest = hashlib.sha256(
            manifest_bytes if manifest_bytes is not None else b""
        ).hexdigest()
    return components, digest


def _manifest_bytes(path: Path, *, is_asar: bool) -> bytes | None:
    """Raw ``package.json`` bytes of a JS input, or ``None`` when absent.

    Failures degrade to ``None``: the JavaScript scan has already warned
    about a missing or broken manifest, and the SBOM simply falls back to
    version-less purls.
    """
    try:
        if is_asar:
            return extract_file(path, "package.json", max_bytes=MAX_FILE_BYTES).data
        manifest = path / "package.json"
        if not manifest.is_file():
            return None
        return manifest.read_bytes()
    except (OSError, AnalysisError):
        return None


def _parse_manifest(data: bytes | None) -> dict[str, Any] | None:
    """Parse manifest bytes as a JSON object, or ``None`` when unusable."""
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _dependency_versions(manifest: dict[str, Any] | None) -> dict[str, str]:
    """Exact versions declared for dependencies, first section wins."""
    versions: dict[str, str] = {}
    if manifest is None:
        return versions
    for section in _DEPENDENCY_SECTIONS:
        block = manifest.get(section)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            if not isinstance(name, str):
                continue
            exact = _exact_version(value)
            if exact is not None and name not in versions:
                versions[name] = exact
    return versions


# ---- binaries ---------------------------------------------------------------


def _binary_components(
    path: Path, warnings: list[str]
) -> tuple[list[SbomComponent], str]:
    """Derive components and the file digest from one binary."""
    try:
        info = load_binary(path)
    except (BinaryLoadError, OSError) as exc:
        raise AnalysisError(f"cannot load binary {path}: {exc}") from exc
    for message in info.warnings:
        _warn(warnings, f"binary {path}: {message}")
    source = str(path)
    components = [
        SbomComponent(
            type="application",
            name=path.stem,
            evidence=_evidence_line("core.loader", "sha256", Confidence.CERTAIN),
            sha256=info.sha256,
            sources=(source,),
        )
    ]
    by_library: dict[str, list[ImportInfo]] = {}
    for imported in info.imports:
        if imported.library:
            by_library.setdefault(_library_name(imported.library), []).append(imported)
    for name in sorted(by_library):
        # Deterministic evidence: the first import (by symbol name) names it.
        first = sorted(by_library[name], key=lambda imported: imported.name)[0].evidence
        evidence = (
            _evidence_line(first.source, first.method, first.confidence)
            if first is not None
            else _evidence_line("core.loader", "import_table", Confidence.HIGH)
        )
        components.append(
            SbomComponent(type="library", name=name, evidence=evidence, sources=(source,))
        )
    return components, info.sha256


def _library_name(library: str) -> str:
    """Reduce an import-table library reference to its display name.

    PE import names are plain ("KERNEL32.dll"); Mach-O load commands carry
    absolute paths ("/usr/lib/libSystem.B.dylib") whose basename is the
    conventional component name.
    """
    for separator in ("/", "\\"):
        if separator in library:
            library = library.rsplit(separator, 1)[-1]
    return library


# ---- shared helpers -----------------------------------------------------------


def _evidence_line(source: str, method: str, confidence: Confidence) -> str:
    """One-line ``source/method/confidence`` justification."""
    return f"{source}/{method}/{confidence.value}"


def _exact_version(value: Any) -> str | None:
    """Return ``value`` when it is an exact version string, else ``None``."""
    if isinstance(value, str) and _EXACT_VERSION_RE.fullmatch(value):
        return value
    return None


def _npm_purl(name: str, version: str | None) -> str:
    """``pkg:npm/<name>`` with ``@<version>`` only when exactly known."""
    if version is not None:
        return f"{_NPM_PURL_PREFIX}{name}@{version}"
    return f"{_NPM_PURL_PREFIX}{name}"


def _file_sha256(path: Path) -> str:
    """Chunked SHA-256 of a file (bounded memory)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AnalysisError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _merge_components(
    components: list[SbomComponent], warnings: list[str]
) -> list[SbomComponent]:
    """Sort by ``(type, name, purl)`` and merge duplicate identities.

    Duplicates share ``(type, name, version, purl)``; merging unions their
    sources. Components that merge with different SHA-256 hashes keep the
    lexicographically smaller hash and say so in a warning -- never silent.
    """
    merged: dict[tuple[str, str, str, str], SbomComponent] = {}
    for component in sorted(components, key=lambda item: item.sort_key):
        key = component.merge_key
        existing = merged.get(key)
        if existing is None:
            merged[key] = component
            continue
        sha256 = existing.sha256
        if (
            sha256 is not None
            and component.sha256 is not None
            and sha256 != component.sha256
        ):
            sha256 = min(sha256, component.sha256)
            _warn(
                warnings,
                f"components named {existing.name!r} merged with different sha256 "
                f"values; keeping {sha256}",
            )
        merged[key] = SbomComponent(
            type=existing.type,
            name=existing.name,
            evidence=existing.evidence,
            version=existing.version,
            purl=existing.purl,
            sha256=sha256,
            sources=tuple(sorted(set(existing.sources) | set(component.sources))),
        )
    return list(merged.values())


def _serial_number(pairs: set[tuple[str, str]]) -> str:
    """``urn:uuid:<uuid5>`` over the sorted, deduplicated input digests."""
    canonical = json.dumps(sorted(pairs), separators=(",", ":"))
    return f"urn:uuid:{uuid.uuid5(_UUID_NAMESPACE, canonical)}"


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)

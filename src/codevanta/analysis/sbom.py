"""CycloneDX 1.6 + SPDX 2.3 SBOM export over the CODEVANTA inventories (stdlib).

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
* **Package manager manifests** found next to the inputs -- npm
  ``package.json``, pip ``requirements.txt``, cargo ``Cargo.toml``, go
  ``go.mod`` and maven ``pom.xml`` -- contribute one component per declared
  dependency, again with versions only when they are exact.
* **Binaries** (PE / ELF / Mach-O / DEX, through
  :class:`~codevanta.core.loader.BinaryLoader`) contribute one ``library``
  component per imported dynamic library named by the import inventory and
  one ``application`` component for the file itself, carrying the SHA-256 of
  its bytes. Versions are never claimed for binaries: the import table does
  not know one.

The aggregate exports in two document formats (:func:`export_sbom` returns
the typed :class:`SbomExport`): CycloneDX 1.6 (``to_dict()``) and SPDX 2.3
JSON (``to_spdx_dict()``). SPDX output carries a fixed epoch ``created``
timestamp so the byte-identical-output guarantee also holds there.

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
import xml.etree.ElementTree
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

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
    "EXPORT_FORMATS",
    "MAX_COMPONENTS",
    "MAX_EXPORT_PACKAGES",
    "MAX_WARNINGS",
    "SPDX_VERSION",
    "SPEC_VERSION",
    "PackageManager",
    "PackageManagerHit",
    "SbomComponent",
    "SbomExport",
    "SbomExportPackage",
    "SbomReport",
    "build_sbom",
    "detect_package_managers",
    "export_sbom",
]

#: CycloneDX specification version emitted by this module.
SPEC_VERSION = "1.6"

#: SPDX specification version emitted by :meth:`SbomReport.to_spdx_dict`.
SPDX_VERSION = "SPDX-2.3"

#: Fixed ``creationInfo.created`` timestamp for SPDX documents: the module's
#: determinism guarantee (byte-identical output for identical inputs) also
#: applies to SPDX, whose ``created`` field is mandatory -- so it is the
#: epoch, honestly fixed, never the wall clock.
SPDX_CREATED = "1970-01-01T00:00:00Z"

#: Document formats :func:`export_sbom` accepts, in stable order.
EXPORT_FORMATS: tuple[str, ...] = ("cyclonedx", "spdx")

#: Packages kept in one :class:`SbomExport` (hard bound; the cut is reported).
MAX_EXPORT_PACKAGES = 128

#: Package managers whose manifests this module detects and parses.
PackageManager = Literal["npm", "pip", "cargo", "go", "maven"]

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

#: purl prefixes per package manager (purl spec type slugs).
_PURL_PREFIXES: dict[str, str] = {
    "npm": "pkg:npm/",
    "pip": "pkg:pypi/",
    "cargo": "pkg:cargo/",
    "go": "pkg:golang/",
    "maven": "pkg:maven/",
}

#: Manifest file names mapped to their package manager, checked at the root
#: of every directory input (deterministic sorted-key order when scanning).
MANIFEST_FILES: dict[str, PackageManager] = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
}

#: PEP 503 name normalisation for pip requirements (``Foo_bar.baz`` -> ``foo-baz``).
_PEP503_RE = re.compile(r"[-_.]+")

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

    def to_spdx_dict(self, index: int) -> dict[str, Any]:
        """The JSON-safe SPDX 2.3 package fragment for this component.

        ``index`` numbers the SPDX ID deterministically. Licenses are
        ``NOASSERTION`` everywhere: the inventories this module aggregates do
        not carry license facts, and SPDX forbids inventing them.
        """
        data: dict[str, Any] = {
            "name": self.name,
            "SPDXID": f"SPDXRef-Package-{index}",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if self.version is not None:
            data["versionInfo"] = self.version
        if self.sha256 is not None:
            data["checksums"] = [{"algorithm": "SHA256", "checksumValue": self.sha256}]
        if self.purl is not None:
            data["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": self.purl,
                }
            ]
        return data


@dataclass(frozen=True)
class PackageManagerHit:
    """One detected package-manager manifest.

    Attributes:
        manager: The package manager the manifest belongs to.
        manifest: Path of the manifest file, as given.
        evidence: Provenance for the detection.
    """

    manager: PackageManager
    manifest: str
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "manager": self.manager,
            "manifest": self.manifest,
            "evidence": self.evidence.to_dict(),
        }


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

    def to_spdx_dict(self) -> dict[str, Any]:
        """The same inventory as an SPDX 2.3 JSON document (deterministic).

        Package order matches :attr:`components`; SPDX IDs are
        ``SPDXRef-Package-<n>`` and the document DESCRIBES every package. The
        ``documentNamespace`` derives from the CycloneDX serial UUID, so the
        same inputs produce the same namespace. ``creationInfo.created`` is
        the fixed epoch (see :data:`SPDX_CREATED`) -- never a wall-clock
        timestamp.
        """
        serial_uuid = self.serial_number.removeprefix("urn:uuid:")
        packages = [
            component.to_spdx_dict(index)
            for index, component in enumerate(self.components, start=1)
        ]
        relationships = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Package-{index}",
            }
            for index in range(1, len(self.components) + 1)
        ]
        return {
            "spdxVersion": SPDX_VERSION,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "codevanta-sbom",
            "documentNamespace": f"urn:codevanta:spdx:{serial_uuid}",
            "creationInfo": {
                "created": SPDX_CREATED,
                "creators": ["Tool: codevanta"],
            },
            "packages": packages,
            "relationships": relationships,
        }

    def to_spdx_json(self) -> str:
        """The SPDX document as pretty JSON (insertion order preserved)."""
        return json.dumps(self.to_spdx_dict(), indent=2)


@dataclass(frozen=True)
class SbomExportPackage:
    """One bounded, typed package row of a :class:`SbomExport`.

    Attributes:
        name: Package name.
        version: Exact version when known, else ``None``.
        licenses: Declared license identifiers; the inventories aggregated
            here carry none, so this is ``("NOASSERTION",)`` unless a future
            source adds facts.
    """

    name: str
    version: str | None
    licenses: tuple[str, ...] = ("NOASSERTION",)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        data: dict[str, Any] = {"name": self.name, "licenses": list(self.licenses)}
        if self.version is not None:
            data["version"] = self.version
        return data


@dataclass(frozen=True)
class SbomExport:
    """A typed, format-tagged SBOM export (CycloneDX or SPDX).

    Attributes:
        format: ``"cyclonedx"`` or ``"spdx"``.
        packages: Typed package rows, bounded by
            :data:`MAX_EXPORT_PACKAGES`.
        licenses: Sorted union of every package's license identifiers.
        truncated: True when the component list was cut to the package cap.
        document: The format-native JSON-safe document (CycloneDX 1.6 or
            SPDX 2.3).
        evidence: Provenance for the export.
    """

    format: str
    packages: tuple[SbomExportPackage, ...]
    licenses: tuple[str, ...]
    truncated: bool
    document: dict[str, Any]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (the native document included)."""
        return {
            "format": self.format,
            "packages": [package.to_dict() for package in self.packages],
            "package_count": len(self.packages),
            "licenses": list(self.licenses),
            "truncated": self.truncated,
            "document": self.document,
            "evidence": self.evidence.to_dict(),
        }


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
            manifest_components, manifest_digest = _manifest_components(
                path, warnings
            )
            components.extend(manifest_components)
            digest = _composite_digest(digest, manifest_digest)
        elif path.suffix.lower() == ".asar" and path.is_file():
            components, digest = _js_components(path, is_asar=True, warnings=warnings)
        elif path.is_file() and path.name in MANIFEST_FILES:
            components, digest = _manifest_components(path, warnings)
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


# ---- package manager manifests ------------------------------------------------


def detect_package_managers(root: Path) -> tuple[PackageManagerHit, ...]:
    """Detect package-manager manifests at ``root`` (offline, bounded).

    A directory is checked for the five known manifests at its root only (no
    recursion -- package trees can be enormous and nested manifests belong to
    vendored copies); a file path is recognised when its *name* is a known
    manifest. Detection is certain: the file exists and carries a canonical
    manifest name.

    Raises:
        AnalysisError: ``root`` cannot be stat'ed.
    """
    try:
        root.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {root}: {exc}") from exc
    hits: list[PackageManagerHit] = []
    if root.is_dir():
        for name in sorted(MANIFEST_FILES):
            candidate = root / name
            if candidate.is_file():
                hits.append(_manifest_hit(MANIFEST_FILES[name], candidate))
    elif root.is_file() and root.name in MANIFEST_FILES:
        hits.append(_manifest_hit(MANIFEST_FILES[root.name], root))
    return tuple(hits)


def _manifest_hit(manager: PackageManager, path: Path) -> PackageManagerHit:
    """Build the detection record for one manifest file."""
    return PackageManagerHit(
        manager=manager,
        manifest=str(path),
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="manifest_detection",
            confidence=Confidence.CERTAIN,
            detail=f"{manager} manifest {path.name!r} exists at the scanned root",
        ),
    )


#: Hard ceiling on dependencies parsed from one manifest.
MAX_PER_MANIFEST = 256


def _manifest_components(
    root: Path, warnings: list[str]
) -> tuple[list[SbomComponent], str]:
    """Parse every detected manifest under ``root`` into components.

    Returns ``(components, digest)`` where ``digest`` is a SHA-256 over the
    sorted ``(name, bytes)`` of all manifests found (deterministic; the empty
    digest when none). Malformed manifests degrade to a warning and no
    components -- a broken file is not evidence of packages.
    """
    collected: list[SbomComponent] = []
    hasher = hashlib.sha256()
    for hit in detect_package_managers(root):
        try:
            data = _manifest_file_bytes(Path(hit.manifest))
        except (OSError, AnalysisError) as exc:
            _warn(warnings, f"manifest {hit.manifest}: cannot read ({exc})")
            continue
        hasher.update(hit.manifest.encode("utf-8", "replace"))
        hasher.update(b"\x00")
        hasher.update(data)
        text = _manifest_text(data)
        if text is None:
            _warn(warnings, f"manifest {hit.manifest}: not valid UTF-8 text; skipped")
            continue
        parsed = _parse_one_manifest(hit.manager, text)
        if parsed is None:
            _warn(
                warnings,
                f"manifest {hit.manifest}: parse failed; no components derived",
            )
            continue
        source = str(hit.manifest)
        evidence = _evidence_line(
            EVIDENCE_SOURCE, f"{hit.manager}_manifest", Confidence.HIGH
        )
        for name, version, purl in parsed[:MAX_PER_MANIFEST]:
            collected.append(
                SbomComponent(
                    type="library",
                    name=name,
                    evidence=evidence,
                    version=version,
                    purl=purl,
                    sources=(source,),
                )
            )
        if len(parsed) > MAX_PER_MANIFEST:
            _warn(
                warnings,
                f"manifest {hit.manifest}: {len(parsed)} dependencies cut to "
                f"the {MAX_PER_MANIFEST}-per-manifest budget",
            )
    return collected, hasher.hexdigest()


def _manifest_file_bytes(path: Path) -> bytes:
    """Read one manifest file, bounded by :data:`MAX_FILE_BYTES`."""
    stat = path.stat()
    if stat.st_size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"manifest {path} is larger than the {MAX_FILE_BYTES}-byte budget"
        )
    return path.read_bytes()


def _manifest_text(data: bytes) -> str | None:
    """Decode manifest bytes as UTF-8 text, or ``None``."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _parse_one_manifest(
    manager: PackageManager, text: str
) -> list[tuple[str, str | None, str | None]] | None:
    """Dispatch to the per-manager parser; ``None`` on unusable syntax."""
    if manager == "npm":
        return _npm_manifest_packages(text)
    if manager == "pip":
        return _pip_manifest_packages(text)
    if manager == "cargo":
        return _cargo_manifest_packages(text)
    if manager == "go":
        return _go_manifest_packages(text)
    return _maven_manifest_packages(text)


def _manifest_purl(manager: PackageManager, name: str, version: str | None) -> str:
    """``pkg:<type>/<name>`` plus ``@<version>`` only when exactly known."""
    prefix = _PURL_PREFIXES[manager]
    if version is not None:
        return f"{prefix}{name}@{version}"
    return f"{prefix}{name}"


def _npm_manifest_packages(
    text: str,
) -> list[tuple[str, str | None, str | None]] | None:
    """Parse ``package.json`` dependency sections; ``None`` on bad JSON."""
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(manifest, dict):
        return None
    packages: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()
    for section in _DEPENDENCY_SECTIONS:
        block = manifest.get(section)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            version = _exact_version(value)
            packages.append((name, version, _manifest_purl("npm", name, version)))
    return packages


#: A pip requirement line: distribution name, optional extras, then the
#: version spec (environment markers were cut before this runs).
_PIP_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"  # distribution name
    r"(?:\[[^\]]*\])?"                                 # optional extras
    r"\s*(.*)$"
)


def _pip_manifest_packages(text: str) -> list[tuple[str, str | None, str | None]]:
    """Parse ``requirements.txt`` lines into ``(name, version, purl)`` rows.

    Whole-line comments, ``-r``/``-e`` style options and environment markers
    are skipped; only ``==`` pins become versions -- ranges are demands, not
    facts, exactly like the npm path.
    """
    packages: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        match = _PIP_REQUIREMENT_RE.match(line)
        if match is None:
            continue
        name = _PEP503_RE.sub("-", match.group(1)).lower()
        if name in seen:
            continue
        seen.add(name)
        rest = match.group(2).strip()
        version: str | None = None
        if rest.startswith("=="):
            version = _exact_version(rest[2:].split(",")[0].strip())
        packages.append((name, version, _manifest_purl("pip", name, version)))
    return packages


_CARGO_SECTION_RE = re.compile(r"^\[([^\]]+)\]\s*$")

#: Cargo tables consulted (``[target.'cfg(..)'.dependencies]`` is matched by
#: its last dotted segment, like cargo's own dependency kinds).
_CARGO_DEPENDENCY_SECTIONS = frozenset(
    {"dependencies", "dev-dependencies", "build-dependencies"}
)


def _cargo_manifest_packages(text: str) -> list[tuple[str, str | None, str | None]]:
    """Parse ``Cargo.toml`` dependency tables (line-oriented TOML subset).

    Handles ``name = "1.2"``, ``name = { version = "1.2", features = [...] }``
    and ``name = { path = "..." }`` (no version). Sections outside the three
    dependency tables, comments and workspace inheritance are skipped; only
    exact versions are claimed.
    """
    packages: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = _CARGO_SECTION_RE.match(line)
        if header is not None:
            section = header.group(1).strip().strip("'\"")
            continue
        if section.rsplit(".", 1)[-1] not in _CARGO_DEPENDENCY_SECTIONS:
            continue
        name, sep, spec = line.partition("=")
        if not sep:
            continue
        name = name.strip().strip("'\"")
        if not name or name in seen:
            continue
        seen.add(name)
        version = _cargo_version(spec.strip().rstrip(","))
        packages.append((name, version, _manifest_purl("cargo", name, version)))
    return packages


def _cargo_version(spec: str) -> str | None:
    """Exact version from a cargo dependency spec, or ``None``."""
    if spec.startswith("{"):
        inner = spec.strip("{}").strip()
        match = re.search(r"version\s*=\s*\"([^\"]+)\"", inner)
        if match is None:
            return None
        spec = match.group(1)
    elif spec.startswith('"') and spec.endswith('"'):
        spec = spec[1:-1]
    if "workspace" in spec or "path" in spec:
        return None
    return _exact_version(spec)


def _go_manifest_packages(
    text: str,
) -> list[tuple[str, str | None, str | None]] | None:
    """Parse ``go.mod`` require blocks; ``None`` when no require exists.

    Both the block form (``require ( ... )``) and single-line requires are
    handled; ``// indirect`` annotations are stripped. A version is claimed
    only when the tag is an exact ``v<digits...>`` (no ``+incompatible``
    fuzz beyond the exact-version rule).
    """
    packages: list[tuple[str, str | None, str | None]] = []
    entries: list[str] = []
    block = re.search(r"require\s*\(([^)]*)\)", text, re.DOTALL)
    if block is not None:
        entries.extend(block.group(1).splitlines())
        tail = re.sub(r"require\s*\([^)]*\)", "", text, flags=re.DOTALL)
        entries.extend(re.findall(r"^\s*require\s+\S+\s+\S+", tail, re.MULTILINE))
    else:
        if "require" not in text:
            return None
        entries.extend(re.findall(r"^\s*require\s+\S+\s+\S+", text, re.MULTILINE))
    seen: set[str] = set()
    for entry in entries:
        entry = entry.split("//", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if parts and parts[0] == "require":
            parts = parts[1:]
        if len(parts) < 2:
            continue
        name, raw_version = parts[0], parts[1]
        if name in seen:
            continue
        seen.add(name)
        version: str | None = None
        if raw_version.startswith("v"):
            stripped = raw_version[1:]
            if _exact_version(stripped) == stripped:
                version = stripped
        packages.append((name, version, _manifest_purl("go", name, version)))
    return packages


def _local_tag(tag: str) -> str:
    """Strip an XML namespace from a tag (``{ns}dependency`` -> ``dependency``)."""
    return tag.rsplit("}", 1)[-1]


def _maven_manifest_packages(
    text: str,
) -> list[tuple[str, str | None, str | None]] | None:
    """Parse ``pom.xml`` ``<dependency>`` entries; ``None`` on bad XML.

    Namespaces are ignored (maven's default POM namespace and none both
    parse); versions that are Maven property references (``${...}``) are
    demands, not facts, so they stay unclaimed.
    """
    try:
        tree = xml.etree.ElementTree.fromstring(text)
    except xml.etree.ElementTree.ParseError:
        return None
    packages: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()
    for element in tree.iter():
        if _local_tag(element.tag) != "dependency":
            continue
        fields = {
            _local_tag(child.tag): (child.text or "").strip() for child in element
        }
        group = fields.get("groupId", "")
        artifact = fields.get("artifactId", "")
        if not group or not artifact:
            continue
        name = f"{group}:{artifact}"
        if name in seen:
            continue
        seen.add(name)
        raw_version = fields.get("version", "")
        version = None
        if raw_version and not raw_version.startswith("${"):
            version = _exact_version(raw_version)
        purl = f"pkg:maven/{group}/{artifact}"
        if version is not None:
            purl = f"{purl}@{version}"
        packages.append((name, version, purl))
    return packages


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


def _composite_digest(first: str, second: str) -> str:
    """Deterministic SHA-256 over two hex digests (order matters, is fixed)."""
    hasher = hashlib.sha256()
    hasher.update(first.encode("ascii"))
    hasher.update(b"\x00")
    hasher.update(second.encode("ascii"))
    return hasher.hexdigest()


def export_sbom(
    report: SbomReport,
    *,
    fmt: str = "cyclonedx",
    max_packages: int = MAX_EXPORT_PACKAGES,
) -> SbomExport:
    """Turn a :class:`SbomReport` into a typed, format-tagged export.

    Args:
        report: The aggregate to export (``build_sbom`` output).
        fmt: ``"cyclonedx"`` (default) or ``"spdx"`` -- the native document
            embedded in the export switches accordingly.
        max_packages: Ceiling on typed package rows kept
            (1..:data:`MAX_EXPORT_PACKAGES`); the cut is reported through
            ``truncated``, never silently.

    Returns:
        The :class:`SbomExport`; ``to_dict()`` is JSON-safe end to end.

    Raises:
        AnalysisError: ``fmt`` is not a supported format or ``max_packages``
            is out of range.
    """
    if fmt not in EXPORT_FORMATS:
        raise AnalysisError(
            f"unsupported format {fmt!r}; expected one of {', '.join(EXPORT_FORMATS)}"
        )
    if isinstance(max_packages, bool) or not isinstance(max_packages, int):
        raise AnalysisError("max_packages must be an int")
    if not 1 <= max_packages <= MAX_EXPORT_PACKAGES:
        raise AnalysisError(
            f"max_packages must be between 1 and {MAX_EXPORT_PACKAGES}"
        )
    kept = report.components[:max_packages]
    truncated = len(report.components) > max_packages
    packages = tuple(
        SbomExportPackage(name=component.name, version=component.version)
        for component in kept
    )
    licenses: tuple[str, ...] = tuple(
        sorted({license for package in packages for license in package.licenses})
    )
    document = (
        report.to_dict() if fmt == "cyclonedx" else report.to_spdx_dict()
    )
    return SbomExport(
        format=fmt,
        packages=packages,
        licenses=licenses,
        truncated=truncated,
        document=document,
        evidence=Evidence(
            source=EVIDENCE_SOURCE,
            method="sbom_export",
            confidence=Confidence.MEDIUM,
            detail=(
                f"{fmt} export of {len(report.components)} component(s); "
                "licenses are NOASSERTION because no aggregated source carries them"
            ),
        ),
    )


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)

"""Static JavaScript / Electron application analysis (offline, pure Python).

Given an extracted application directory or an ``.asar`` archive, this module
inventories the JavaScript surface *without executing anything*:

* **Modules** -- every ``.js`` / ``.cjs`` / ``.mjs`` file, bounded by count,
  depth, per-file size and a whole-scan byte budget.
* **Imports** -- CommonJS ``require("x")``, static ESM ``import ... from "x"``,
  ``export ... from "x"`` and dynamic ``import("x")``, each classified as
  ``relative``, ``bare`` (an npm package name) or ``builtin`` (a Node core
  module), with the line it appears on. Relative specs are resolved against
  the scanned file set when the target is one of them.
* **Electron boundaries** -- files that import ``electron`` get a heuristic
  process role (``main`` / ``renderer`` / ``preload`` / ``mixed``) from the
  Electron APIs they reference, and every ``ipcMain.*`` / ``ipcRenderer.*``
  call with a literal channel string becomes an ``IpcSite`` with its line.
  Channels are then paired across sides by exact name: an ``IpcPair`` is
  *medium* confidence because a shared string is strong evidence of a boundary
  but not proof the two endpoints agree on semantics.
* **Package facts** -- ``name``, ``main`` and the declared ``electron``
  version from the root ``package.json`` when present.

Guarantees:

* Nothing here executes, writes, or follows symlinks; directory walks use
  ``os.walk(..., followlinks=False)`` and ASAR reads go through the bounded
  :mod:`codevanta.analysis.asar` parser.
* Bounded work: rows, depth, per-file bytes, total bytes, per-file imports and
  IPC sites all carry hard caps, and every cap that fires is reported through
  ``truncated`` flags, counts or warnings -- never silently.
* Malformed input (missing path, wrong kind, unreadable bytes, broken
  ``package.json``) degrades to a warning where the rest of the scan can
  continue, and raises :class:`~codevanta.core.report.AnalysisError` where it
  cannot.
* Literal text findings are *certain* (the string is provably in the file at
  that line); classifications built on top of them (roles, channel pairing,
  bare-name → package mapping) are *medium* and say so in their evidence.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from codevanta.analysis.asar import extract_file, list_archive
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "DEFAULT_MAX_FILES",
    "EVIDENCE_SOURCE",
    "IpcPair",
    "IpcSite",
    "JsAppReport",
    "JsFile",
    "JsImport",
    "MAX_DEPTH",
    "MAX_FILE_BYTES",
    "MAX_FILES",
    "MAX_IPC_SITES_PER_FILE",
    "MAX_IMPORTS_PER_FILE",
    "MAX_TOTAL_BYTES",
    "MAX_WARNINGS",
    "NODE_BUILTINS",
    "PackageFacts",
    "SKIP_DIRS",
    "analyze_javascript_app",
]

#: Hard ceiling on file rows kept in one report. The walk keeps counting
#: beyond this (totals stay honest) but no more rows are collected.
MAX_FILES = 512

#: Hard ceiling on directory-walk depth (path components below the root).
MAX_DEPTH = 64

#: Hard ceiling on bytes read from one file; larger files are skipped with a
#: warning instead of read (bundled/minified giants fail this on purpose).
MAX_FILE_BYTES = 1024 * 1024

#: Hard ceiling on total bytes read by one scan; reaching it stops the scan
#: and sets ``truncated``.
MAX_TOTAL_BYTES = 32 * 1024 * 1024

#: Hard ceiling on import rows kept per file (counting continues past it).
MAX_IMPORTS_PER_FILE = 256

#: Hard ceiling on IPC sites kept per file (counting continues past it).
MAX_IPC_SITES_PER_FILE = 128

#: Hard ceiling on warnings kept in the report.
MAX_WARNINGS = 32

#: Directory names that are counted and pruned, never entered.
SKIP_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".cache"})

#: Node core modules accepted as builtin specifiers without the ``node:``
#: prefix (the prefix itself is always builtin).
NODE_BUILTINS = frozenset(
    {
        "assert", "buffer", "child_process", "cluster", "console", "constants",
        "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
        "https", "inspector", "module", "net", "os", "path", "perf_hooks",
        "process", "punycode", "querystring", "readline", "repl", "stream",
        "string_decoder", "sys", "timers", "tls", "tty", "url", "util", "v8",
        "vm", "wasi", "worker_threads", "zlib",
    }
)

#: Default (and only) ceiling accepted for ``max_files``; the argument exists
#: so CLI/MCP callers can lower it, matching the other lanes' shape.
DEFAULT_MAX_FILES = MAX_FILES

#: Evidence source shared by every record in this module.
EVIDENCE_SOURCE = "js.static"

_JS_SUFFIXES = frozenset({".js", ".cjs", ".mjs"})

_REQUIRE_RE = re.compile(r"\brequire\s*\(\s*(['\"])([^'\"]+)\1")
_IMPORT_RE = re.compile(r"\bimport\s+(?:[\w$*{},\s]+?\s+from\s+)?(['\"])([^'\"]+)\1")
_EXPORT_FROM_RE = re.compile(r"\bexport\s+(?:\*|\{[^}]*\})\s*(?:[\w$]+\s+)?from\s+(['\"])([^'\"]+)\1")
_DYNAMIC_IMPORT_RE = re.compile(r"\bimport\s*\(\s*(['\"])([^'\"]+)\1")

_ELECTRON_SPECIFIERS = frozenset({"electron"})

#: Unambiguous Electron API names counted per file (``app``, ``net``, ... are
#: deliberately absent: as bare words they match ordinary code and comments).
_ELECTRON_APIS = frozenset(
    {
        "ipcMain", "ipcRenderer", "contextBridge", "BrowserWindow",
        "BrowserView", "Tray", "globalShortcut", "powerMonitor",
        "nativeImage", "webFrame",
    }
)
_ELECTRON_API_RE = re.compile(r"\b(" + "|".join(sorted(_ELECTRON_APIS)) + r")\b")
_EXPOSE_IN_MAIN_WORLD_RE = re.compile(r"\bexposeInMainWorld\b")
_ELECTRON_IMPORT_RE = re.compile(
    r"\b(?:require\s*\(\s*|import\s+(?:[\w$*{},\s]*?from\s+)?)(['\"])electron\1"
)

_MAIN_ROLE_MARKERS = frozenset({"ipcMain", "BrowserWindow", "Tray", "globalShortcut", "powerMonitor"})
_RENDERER_ROLE_MARKERS = frozenset({"ipcRenderer", "webFrame"})

_IPC_METHODS = (
    "on", "once", "handle", "handleOnce", "send", "sendSync", "invoke",
    "sendToHost", "removeListener", "removeAllListeners",
)
_IPC_CALL_TEMPLATE = r"\b(ipcMain|ipcRenderer)\.(%s)\s*\(\s*(['\"])([^'\"]*)\3"
_IPC_CALL_RE = re.compile(_IPC_CALL_TEMPLATE % "|".join(_IPC_METHODS))


@dataclass(frozen=True)
class JsImport:
    """One import site in one file.

    Attributes:
        spec: The literal specifier as written (``./util``, ``lodash``,
            ``node:fs``).
        kind: ``relative``, ``bare`` or ``builtin`` -- a classification, so
            the record's confidence lives on the owning file's evidence.
        line: 1-based line number of the site.
        resolved: Posix path of the scanned file this specifier resolves to,
            or ``None`` when it does not resolve inside the scanned set.
        syntax: ``require``, ``import``, ``export-from`` or ``import-dynamic``.
    """

    spec: str
    kind: str
    line: int
    syntax: str
    resolved: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "spec": self.spec,
            "kind": self.kind,
            "syntax": self.syntax,
            "line": self.line,
        }
        if self.resolved is not None:
            data["resolved"] = self.resolved
        return data


@dataclass(frozen=True)
class IpcSite:
    """One ``ipcMain.*`` / ``ipcRenderer.*`` call with a literal channel."""

    side: str  # "main" | "renderer"
    api: str  # e.g. "ipcMain.handle"
    channel: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {"side": self.side, "api": self.api, "channel": self.channel, "line": self.line}


@dataclass(frozen=True)
class JsFile:
    """One scanned JavaScript file."""

    path: str  # posix-style, relative to the root
    size: int
    imports: tuple[JsImport, ...]
    ipc: tuple[IpcSite, ...]
    electron_apis: tuple[str, ...]
    uses_electron: bool
    role: str  # "main" | "renderer" | "preload" | "mixed" | "unknown"
    role_markers: tuple[str, ...]
    evidence: Evidence
    imports_truncated: bool = False
    ipc_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "size": self.size,
            "role": self.role,
            "role_markers": list(self.role_markers),
            "role_confidence": (
                Confidence.MEDIUM.value
                if self.role in {"main", "renderer", "preload", "mixed"}
                else Confidence.UNKNOWN.value
            ),
            "imports": [imp.to_dict() for imp in self.imports],
            "ipc": [site.to_dict() for site in self.ipc],
            "electron_apis": list(self.electron_apis),
            "uses_electron": self.uses_electron,
            "evidence": self.evidence.to_dict(),
        }
        if self.imports_truncated:
            data["imports_truncated"] = True
        if self.ipc_truncated:
            data["ipc_truncated"] = True
        return data


@dataclass(frozen=True)
class IpcPair:
    """One channel name used on both the main and the renderer side."""

    channel: str
    main: tuple[IpcSite, ...]
    renderer: tuple[IpcSite, ...]
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "main": [site.to_dict() for site in self.main],
            "renderer": [site.to_dict() for site in self.renderer],
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class PackageFacts:
    """Facts read from the root ``package.json``."""

    name: str | None
    main: str | None
    electron_version: str | None
    evidence: Evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "main": self.main,
            "electron_version": self.electron_version,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class JsAppReport:
    """The bounded inventory of one JavaScript/Electron application."""

    root: str
    kind: str  # "directory" | "asar"
    files: tuple[JsFile, ...]
    package: PackageFacts | None
    evidence: Evidence
    ipc_pairs: tuple[IpcPair, ...] = field(default_factory=tuple)
    main_only: tuple[IpcSite, ...] = field(default_factory=tuple)
    renderer_only: tuple[IpcSite, ...] = field(default_factory=tuple)
    file_count: int = 0  # JS files found (rows kept + rows cut)
    skipped_dirs: int = 0
    skipped_large_files: int = 0
    skipped_unpacked: int = 0
    skipped_unreadable: int = 0
    total_scanned_bytes: int = 0
    truncated: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        import_kinds = {"relative": 0, "bare": 0, "builtin": 0}
        packages: dict[str, int] = {}
        for js_file in self.files:
            for imp in js_file.imports:
                import_kinds[imp.kind] += 1
                if imp.kind == "bare":
                    packages[_bare_package(imp.spec)] = (
                        packages.get(_bare_package(imp.spec), 0) + 1
                    )
        return {
            "root": self.root,
            "kind": self.kind,
            "file_count": self.file_count,
            "files_scanned": len(self.files),
            "skipped": {
                "directories": self.skipped_dirs,
                "large_files": self.skipped_large_files,
                "unpacked": self.skipped_unpacked,
                "unreadable": self.skipped_unreadable,
            },
            "total_scanned_bytes": self.total_scanned_bytes,
            "truncated": self.truncated,
            "package": self.package.to_dict() if self.package else None,
            "files": [f.to_dict() for f in self.files],
            "import_kinds": import_kinds,
            "external_packages": dict(sorted(packages.items())),
            "ipc": {
                "pairs": [pair.to_dict() for pair in self.ipc_pairs],
                "main_only": [site.to_dict() for site in self.main_only],
                "renderer_only": [site.to_dict() for site in self.renderer_only],
            },
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _bare_package(spec: str) -> str:
    """Reduce a bare specifier to its package name (``@scope/name`` aware)."""
    parts = PurePosixPath(spec).parts
    if spec.startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else spec


def classify_spec(spec: str) -> str:
    """Classify one import specifier (medium confidence, name-shape only)."""
    if spec.startswith(("./", "../")) or spec in {".", ".."}:
        return "relative"
    if spec.startswith("node:") or PurePosixPath(spec).parts[0] in NODE_BUILTINS:
        return "builtin"
    return "bare"


def _line_of(text: str, index: int) -> int:
    """1-based line number of ``index`` within ``text``."""
    return text.count("\n", 0, index) + 1


def _collect_imports(text: str) -> tuple[list[JsImport], bool]:
    """Scan one file's text for import sites (bounded per file)."""
    found: list[JsImport] = []
    seen: set[tuple[str, str, int]] = set()
    truncated = False
    patterns = (
        (_REQUIRE_RE, "require"),
        (_IMPORT_RE, "import"),
        (_EXPORT_FROM_RE, "export-from"),
        (_DYNAMIC_IMPORT_RE, "import-dynamic"),
    )
    for pattern, syntax in patterns:
        for match in pattern.finditer(text):
            spec = match.group(2)
            line = _line_of(text, match.start())
            key = (spec, syntax, line)
            if key in seen:
                continue
            seen.add(key)
            if len(found) >= MAX_IMPORTS_PER_FILE:
                truncated = True
                break
            found.append(JsImport(spec=spec, kind=classify_spec(spec), line=line, syntax=syntax))
        else:
            continue
        break
    found.sort(key=lambda imp: (imp.line, imp.spec))
    return found, truncated


def _collect_ipc(text: str) -> tuple[list[IpcSite], bool]:
    """Scan one file's text for ``ipcMain.*`` / ``ipcRenderer.*`` calls.

    Returns the literal-channel sites and a truncation flag. Calls whose
    channel argument is not a plain string literal (a variable, a template
    with holes) are not sites and are simply not reported -- the scan only
    ever claims what is literally in the text.
    """
    sites: list[IpcSite] = []
    truncated = False
    for match in _IPC_CALL_RE.finditer(text):
        if len(sites) >= MAX_IPC_SITES_PER_FILE:
            truncated = True
            break
        channel = match.group(4)
        if not channel:
            continue
        side = "main" if match.group(1) == "ipcMain" else "renderer"
        sites.append(
            IpcSite(
                side=side,
                api=f"{match.group(1)}.{match.group(2)}",
                channel=channel,
                line=_line_of(text, match.start()),
            )
        )
    sites.sort(key=lambda site: (site.line, site.api))
    return sites, truncated


def _role_for(uses_electron: bool, apis: tuple[str, ...], exposes: bool) -> tuple[str, tuple[str, ...]]:
    """Heuristic process role from the Electron APIs a file references."""
    markers = sorted(set(apis))
    if not uses_electron:
        return "unknown", ()
    if exposes:
        markers = sorted(set(markers) | {"exposeInMainWorld"})
    main = bool(_MAIN_ROLE_MARKERS.intersection(markers))
    renderer = bool(_RENDERER_ROLE_MARKERS.intersection(markers)) or exposes
    if main and renderer:
        return "mixed", tuple(markers)
    if main:
        return "main", tuple(markers)
    if exposes:
        return "preload", tuple(markers)
    if renderer:
        return "renderer", tuple(markers)
    return "unknown", tuple(markers)


def _scan_text(path: str, text: str) -> JsFile:
    """Build one :class:`JsFile` from decoded source text."""
    imports, imports_truncated = _collect_imports(text)
    ipc_sites, ipc_truncated = _collect_ipc(text)
    uses_electron = _ELECTRON_IMPORT_RE.search(text) is not None
    apis = tuple(sorted({m.group(1) for m in _ELECTRON_API_RE.finditer(text)}))
    role, markers = _role_for(uses_electron, apis, bool(_EXPOSE_IN_MAIN_WORLD_RE.search(text)))
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="module_scan",
        confidence=Confidence.CERTAIN,
        detail="literal import/ipc/electron matches in decoded text",
        extra={
            "path": path,
            "imports": len(imports),
            "ipc_sites": len(ipc_sites),
            "electron": uses_electron,
        },
    )
    return JsFile(
        path=path,
        size=len(text.encode("utf-8", errors="replace")),
        imports=tuple(imports),
        ipc=tuple(ipc_sites),
        electron_apis=apis,
        uses_electron=uses_electron,
        role=role,
        role_markers=markers,
        evidence=evidence,
        imports_truncated=imports_truncated,
        ipc_truncated=ipc_truncated,
    )


def _decode(data: bytes, path: str) -> str:
    """Decode source bytes as UTF-8 (a BOM is tolerated), or raise typed."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"javascript file {path!r} is not valid UTF-8: {exc}") from exc


def _parse_package_json(text: str) -> PackageFacts:
    """Read name/main/electron from ``package.json`` text (typed errors)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"package.json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AnalysisError("package.json must contain a JSON object")
    name = data.get("name")
    main = data.get("main")
    version = None
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if isinstance(block, dict) and isinstance(block.get("electron"), str):
            version = block["electron"]
            break
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="package_json",
        confidence=Confidence.CERTAIN,
        extra={"electron_version": version},
    )
    return PackageFacts(
        name=name if isinstance(name, str) else None,
        main=main if isinstance(main, str) else None,
        electron_version=version,
        evidence=evidence,
    )


def _resolve_relative(report_files: dict[str, JsFile]) -> None:
    """Resolve relative import specs against the scanned file set, in place.

    Pure rewrite of the ``resolved`` field is impossible on frozen dataclasses,
    so files with resolvable imports are rebuilt once, here.
    """
    resolution_pass: dict[str, JsFile] = {}
    for js_file in report_files.values():
        directory = PurePosixPath(js_file.path).parent
        changed = False
        imports: list[JsImport] = []
        for imp in js_file.imports:
            if imp.kind != "relative" or imp.resolved is not None:
                imports.append(imp)
                continue
            target = _resolve_spec(directory, imp.spec, report_files)
            if target is None:
                imports.append(imp)
                continue
            changed = True
            imports.append(
                JsImport(spec=imp.spec, kind=imp.kind, line=imp.line, syntax=imp.syntax, resolved=target)
            )
        if changed:
            resolution_pass[js_file.path] = JsFile(
                path=js_file.path,
                size=js_file.size,
                imports=tuple(imports),
                ipc=js_file.ipc,
                electron_apis=js_file.electron_apis,
                uses_electron=js_file.uses_electron,
                role=js_file.role,
                role_markers=js_file.role_markers,
                evidence=js_file.evidence,
                imports_truncated=js_file.imports_truncated,
                ipc_truncated=js_file.ipc_truncated,
            )
    report_files.update(resolution_pass)


def _resolve_spec(directory: PurePosixPath, spec: str, files: dict[str, JsFile]) -> str | None:
    """Resolve one relative specifier to a scanned file path, Node-style."""
    base = PurePosixPath(*directory.parts, *PurePosixPath(spec).parts).as_posix()
    candidates = (
        base,
        base + ".js",
        base + ".cjs",
        base + ".mjs",
        base + "/index.js",
        base + "/index.cjs",
        base + "/index.mjs",
    )
    for candidate in candidates:
        normalised = posixpath.normpath(candidate)
        if normalised.lstrip("./") in files:
            return normalised.lstrip("./")
    return None


def _pair_channels(sites_by_file: dict[str, JsFile]) -> tuple[tuple[IpcPair, ...], tuple[IpcSite, ...], tuple[IpcSite, ...]]:
    """Pair IPC channels across sides by exact channel-name equality."""
    main: dict[str, list[IpcSite]] = {}
    renderer: dict[str, list[IpcSite]] = {}
    for js_file in sites_by_file.values():
        for site in js_file.ipc:
            bucket = main if site.side == "main" else renderer
            bucket.setdefault(site.channel, []).append(site)
    pairs: list[IpcPair] = []
    main_only: list[IpcSite] = []
    renderer_only: list[IpcSite] = []
    for channel in sorted(set(main) | set(renderer)):
        left = main.get(channel, [])
        right = renderer.get(channel, [])
        if left and right:
            pairs.append(
                IpcPair(
                    channel=channel,
                    main=tuple(sorted(left, key=lambda s: (s.api, s.line))),
                    renderer=tuple(sorted(right, key=lambda s: (s.api, s.line))),
                    evidence=Evidence(
                        source=EVIDENCE_SOURCE,
                        method="channel_name_match",
                        confidence=Confidence.MEDIUM,
                        detail="same channel string on both sides; endpoints not verified",
                    ),
                )
            )
        elif left:
            main_only.extend(left)
        else:
            renderer_only.extend(right)
    order = lambda site: (site.channel, site.api, site.line)  # noqa: E731 -- local, single use
    return tuple(pairs), tuple(sorted(main_only, key=order)), tuple(sorted(renderer_only, key=order))


def analyze_javascript_app(path: Path, *, max_files: int = DEFAULT_MAX_FILES) -> JsAppReport:
    """Inventory one JavaScript/Electron application directory or ASAR archive.

    Args:
        path: Application root directory, or a path to an ``.asar`` archive.
        max_files: Ceiling on file rows kept (1..MAX_FILES); the walk keeps
            counting beyond it so the totals stay honest.

    Raises:
        AnalysisError: ``path`` does not exist, is neither a directory nor an
            ``.asar`` file, an ``.asar`` header is malformed, or a scanned
            file is not valid UTF-8 (the scan stops rather than guess).
    """
    if not 1 <= max_files <= MAX_FILES:
        raise AnalysisError(f"max_files must be between 1 and {MAX_FILES}")
    try:
        path.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat {path}: {exc}") from exc
    if path.is_dir():
        return _scan_directory(path, max_files)
    if path.is_file() and path.suffix.lower() == ".asar":
        return _scan_asar(path, max_files)
    raise AnalysisError(
        f"not a javascript application root: {path} is neither a directory nor an .asar archive"
    )


def _scan_directory(root: Path, max_files: int) -> JsAppReport:
    """Walk an extracted application directory (bounded, symlink-free)."""
    files: dict[str, JsFile] = {}
    warnings: list[str] = []
    state = {
        "file_count": 0,
        "skipped_dirs": 0,
        "skipped_large": 0,
        "skipped_unreadable": 0,
        "bytes": 0,
        "truncated": False,
    }
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = PurePosixPath(Path(dirpath).relative_to(root).as_posix())
        depth = 0 if rel_dir.as_posix() == "." else len(rel_dir.parts)
        if depth >= MAX_DEPTH:
            dirnames[:] = []
            state["truncated"] = True
            _warn(warnings, f"directory depth cap {MAX_DEPTH} reached at {rel_dir.as_posix()!r}")
        dirnames[:] = sorted(d for d in dirnames if not _prune(d, state))
        stop = False
        for name in sorted(filenames):
            rel = (rel_dir / name).as_posix() if rel_dir.as_posix() != "." else name
            if Path(name).suffix.lower() not in _JS_SUFFIXES:
                continue
            state["file_count"] += 1
            if len(files) >= max_files:
                state["truncated"] = True
                continue
            absolute = Path(dirpath) / name
            try:
                size = absolute.stat().st_size
            except OSError as exc:
                state["skipped_unreadable"] += 1
                _warn(warnings, f"cannot stat {rel!r}: {exc}")
                continue
            if size > MAX_FILE_BYTES:
                state["skipped_large"] += 1
                _warn(
                    warnings,
                    f"skipped {rel!r}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte per-file cap",
                )
                continue
            if state["bytes"] + size > MAX_TOTAL_BYTES:
                state["truncated"] = True
                _warn(warnings, f"stopped at {rel!r}: whole-scan byte budget {MAX_TOTAL_BYTES} reached")
                stop = True
                break
            try:
                text = _decode(absolute.read_bytes(), rel)
            except OSError as exc:
                state["skipped_unreadable"] += 1
                _warn(warnings, f"cannot read {rel!r}: {exc}")
                continue
            except AnalysisError as exc:
                _warn(warnings, str(exc))
                state["skipped_unreadable"] += 1
                continue
            state["bytes"] += size
            files[rel] = _scan_text(rel, text)
        if stop:
            break
    package = _read_root_package_json(root, warnings)
    return _finish(str(root), "directory", files, package, state, warnings)


def _prune(dirname: str, state: dict[str, int]) -> bool:
    """Count and prune skipped directory names."""
    if dirname in SKIP_DIRS:
        state["skipped_dirs"] += 1
        return True
    return False


def _read_root_package_json(root: Path, warnings: list[str]) -> PackageFacts | None:
    """Parse ``<root>/package.json`` when present; missing is a warning."""
    manifest = root / "package.json"
    if not manifest.is_file():
        _warn(warnings, "no package.json at the application root")
        return None
    try:
        text = _decode(manifest.read_bytes(), "package.json")
        return _parse_package_json(text)
    except OSError as exc:
        _warn(warnings, f"cannot read package.json: {exc}")
        return None
    except AnalysisError as exc:
        _warn(warnings, str(exc))
        return None


def _scan_asar(root: Path, max_files: int) -> JsAppReport:
    """Inventory the JavaScript files inside one ``.asar`` archive."""
    listing = list_archive(root)
    files: dict[str, JsFile] = {}
    warnings: list[str] = []
    state = {
        "file_count": 0,
        "skipped_dirs": 0,
        "skipped_large": 0,
        "skipped_unpacked": 0,
        "skipped_unreadable": 0,
        "bytes": 0,
        "truncated": listing.truncated,
    }
    if listing.truncated:
        _warn(warnings, "asar listing truncated; totals may be incomplete")
    for entry in listing.files:
        if Path(entry.path).suffix.lower() not in _JS_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in PurePosixPath(entry.path).parts[:-1]):
            state["skipped_dirs"] += 1
            continue
        state["file_count"] += 1
        if len(files) >= max_files:
            state["truncated"] = True
            continue
        if entry.unpacked:
            state["skipped_unpacked"] += 1
            _warn(warnings, f"skipped {entry.path!r}: unpacked entries live outside the archive")
            continue
        if entry.size > MAX_FILE_BYTES:
            state["skipped_large"] += 1
            _warn(
                warnings,
                f"skipped {entry.path!r}: {entry.size} bytes exceeds the {MAX_FILE_BYTES}-byte per-file cap",
            )
            continue
        if state["bytes"] + entry.size > MAX_TOTAL_BYTES:
            state["truncated"] = True
            _warn(warnings, f"stopped at {entry.path!r}: whole-scan byte budget {MAX_TOTAL_BYTES} reached")
            break
        try:
            extracted = extract_file(root, entry.path, max_bytes=MAX_FILE_BYTES)
            text = _decode(extracted.data, entry.path)
        except AnalysisError as exc:
            state["skipped_unreadable"] += 1
            _warn(warnings, str(exc))
            continue
        state["bytes"] += entry.size
        files[entry.path] = _scan_text(entry.path, text)
    package = _asar_package(root, warnings)
    return _finish(str(root), "asar", files, package, state, warnings)


def _asar_package(root: Path, warnings: list[str]) -> PackageFacts | None:
    """Read the archive's root ``package.json`` through the bounded parser."""
    try:
        extracted = extract_file(root, "package.json", max_bytes=MAX_FILE_BYTES)
        text = _decode(extracted.data, "package.json")
        return _parse_package_json(text)
    except AnalysisError as exc:
        _warn(warnings, f"no readable package.json in the archive: {exc}")
        return None


def _warn(warnings: list[str], message: str) -> None:
    """Append one warning unless the cap has been reached."""
    if len(warnings) < MAX_WARNINGS:
        warnings.append(message)


def _finish(
    root: str,
    kind: str,
    files: dict[str, JsFile],
    package: PackageFacts | None,
    state: dict[str, int],
    warnings: list[str],
) -> JsAppReport:
    """Resolve relative imports, pair IPC channels, and assemble the report."""
    ordered = {rel: files[rel] for rel in sorted(files)}
    _resolve_relative(ordered)
    pairs, main_only, renderer_only = _pair_channels(ordered)
    evidence = Evidence(
        source=EVIDENCE_SOURCE,
        method="bounded_walk" if kind == "directory" else "asar_listing",
        confidence=Confidence.CERTAIN,
        detail="every kept row was read and decoded; classifications carry their own confidence",
        extra={"kind": kind, "files": len(ordered), "bytes": state["bytes"]},
    )
    return JsAppReport(
        root=root,
        kind=kind,
        files=tuple(ordered.values()),
        package=package,
        ipc_pairs=pairs,
        main_only=main_only,
        renderer_only=renderer_only,
        file_count=state["file_count"],
        skipped_dirs=state["skipped_dirs"],
        skipped_large_files=state["skipped_large"],
        skipped_unpacked=state.get("skipped_unpacked", 0),
        skipped_unreadable=state["skipped_unreadable"],
        total_scanned_bytes=state["bytes"],
        truncated=bool(state["truncated"]),
        warnings=tuple(warnings),
        evidence=evidence,
    )

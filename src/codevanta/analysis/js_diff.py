"""Version comparison for two JavaScript/Electron application inventories.

The comparator answers "what changed between two builds of this app?" at the
level :func:`codevanta.analysis.javascript.analyze_javascript_app` describes:
which modules appeared or disappeared, which files changed their import set or
process role, which dependencies were added, removed or re-versioned, and
which IPC channels appeared, disappeared or lost one side of their pair.

The comparison is static and offline, like the inventory it reads. Every list
is bounded, every finding names both sides, and the evidence record says the
comparison is a *shape* measure: an unchanged module list does not mean
unchanged behaviour, because file contents are not hashed into the comparison
(the inventory keeps imports and IPC sites, not file digests).

Typical use: two checkouts of the same app (or one extracted .asar per
release), compared to review a vendor update before shipping it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codevanta.analysis.javascript import (
    DEFAULT_MAX_FILES,
    analyze_javascript_app,
)
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

#: Cap on each reported list, so one noisy diff cannot flood a report.
MAX_ROWS = 200

__all__ = [
    "MAX_ROWS",
    "FileChange",
    "IpcChange",
    "JsAppsCompare",
    "PackageChange",
    "compare_js_apps",
]


@dataclass(frozen=True)
class FileChange:
    """One module that exists on only one side, or changed shape on both."""

    path: str
    kind: str  # "added" | "removed" | "changed"
    role_left: str | None = None
    role_right: str | None = None
    imports_added: tuple[str, ...] = ()
    imports_removed: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": self.path, "kind": self.kind}
        if self.kind == "changed":
            payload["role_left"] = self.role_left
            payload["role_right"] = self.role_right
            payload["imports_added"] = list(self.imports_added)
            payload["imports_removed"] = list(self.imports_removed)
        return payload


@dataclass(frozen=True)
class PackageChange:
    """One dependency added, removed, or pinned to a different version."""

    name: str
    kind: str  # "added" | "removed" | "version"
    version_left: str | None = None
    version_right: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "kind": self.kind}
        if self.kind == "version":
            payload["version_left"] = self.version_left
            payload["version_right"] = self.version_right
        return payload


@dataclass(frozen=True)
class IpcChange:
    """One IPC channel that appeared, disappeared, or lost a side of its pair."""

    channel: str
    kind: str  # "added" | "removed" | "main_only" | "renderer_only"
    files: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": self.channel, "kind": self.kind}
        if self.files:
            payload["files"] = list(self.files)
        return payload


@dataclass(frozen=True)
class JsAppsCompare:
    """The bounded delta between two JavaScript application inventories."""

    left_root: str
    right_root: str
    left_kind: str
    right_kind: str
    files_added: tuple[FileChange, ...] = ()
    files_removed: tuple[FileChange, ...] = ()
    files_changed: tuple[FileChange, ...] = ()
    role_changes: tuple[FileChange, ...] = ()
    packages: tuple[PackageChange, ...] = ()
    ipc: tuple[IpcChange, ...] = ()
    left_file_count: int = 0
    right_file_count: int = 0
    truncated: bool = False
    warnings: tuple[str, ...] = ()
    evidence: Evidence = field(
        default_factory=lambda: Evidence(
            source="js.version_compare",
            method="set-diff over two bounded static inventories",
            confidence=Confidence.MEDIUM,
        )
    )

    @property
    def identical(self) -> bool:
        """True when no bounded delta was observed (not a behaviour claim)."""
        return not (
            self.files_added
            or self.files_removed
            or self.files_changed
            or self.packages
            or self.ipc
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": {"root": self.left_root, "kind": self.left_kind},
            "right": {"root": self.right_root, "kind": self.right_kind},
            "identical": self.identical,
            "files": {
                "added": [row.to_dict() for row in self.files_added],
                "removed": [row.to_dict() for row in self.files_removed],
                "changed": [row.to_dict() for row in self.files_changed],
                "role_changes": [row.to_dict() for row in self.role_changes],
                "left_count": self.left_file_count,
                "right_count": self.right_file_count,
            },
            "packages": [row.to_dict() for row in self.packages],
            "ipc": [row.to_dict() for row in self.ipc],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "evidence": self.evidence.to_dict(),
        }


def _file_rows(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Index one inventory's file rows by path."""
    rows: dict[str, dict[str, Any]] = {}
    for row in payload.get("files", ()):
        if isinstance(row, Mapping):
            path = row.get("path")
            if isinstance(path, str) and path:
                rows[path] = row
    return rows


def _import_set(row: Mapping[str, Any]) -> frozenset[str]:
    """The (kind, spec) signature of one file's imports."""
    signature: set[str] = set()
    for imp in row.get("imports", ()):
        if isinstance(imp, Mapping):
            spec = imp.get("spec")
            if isinstance(spec, str) and spec:
                signature.add(f"{imp.get('kind', 'unknown')}:{spec}")
    return frozenset(signature)


def _package_versions(payload: Mapping[str, Any]) -> dict[str, str]:
    """The dependency pins one inventory's package.json declared."""
    package = payload.get("package")
    if not isinstance(package, Mapping):
        return {}
    versions: dict[str, str] = {}
    dependencies = package.get("dependencies")
    if isinstance(dependencies, Mapping):
        for name, version in dependencies.items():
            if isinstance(name, str) and isinstance(version, str):
                versions[name] = version
    return versions


def _channel_index(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Index every IPC channel the inventory saw, paired or one-sided.

    Pairs contribute both sides; the ``main_only`` / ``renderer_only`` lists
    contribute their side, so a channel that never found its counterpart is
    still visible to a version diff.
    """
    section = payload.get("ipc")
    if not isinstance(section, Mapping):
        return {}
    channels: dict[str, dict[str, Any]] = {}

    def _touch(channel: str, side: str, file: str | None) -> None:
        row = channels.setdefault(channel, {"main": False, "renderer": False, "files": set()})
        row[side] = True
        if file:
            row["files"].add(file)

    for pair in section.get("pairs", ()):
        if not isinstance(pair, Mapping):
            continue
        channel = pair.get("channel")
        if not isinstance(channel, str) or not channel:
            continue
        for side in ("main", "renderer"):
            for site in pair.get(side, ()):
                if isinstance(site, Mapping):
                    _touch(
                        channel,
                        side,
                        site.get("file") if isinstance(site.get("file"), str) else None,
                    )
    for key, side in (("main_only", "main"), ("renderer_only", "renderer")):
        for site in section.get(key, ()):
            if isinstance(site, Mapping):
                channel = site.get("channel")
                if isinstance(channel, str) and channel:
                    _touch(
                        channel,
                        side,
                        site.get("file") if isinstance(site.get("file"), str) else None,
                    )
    return channels


def _bounded_rows(
    rows: list[Any], label: str, truncated: list[bool], warnings: list[str]
) -> tuple[Any, ...]:
    """Cap one list at :data:`MAX_ROWS`, recording the cut in warnings."""
    if len(rows) > MAX_ROWS:
        truncated[0] = True
        warnings.append(f"{label}: {len(rows)} rows found, reporting the first {MAX_ROWS}")
        return tuple(rows[:MAX_ROWS])
    return tuple(rows)


def compare_js_apps(
    left_path: str | Path,
    right_path: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
) -> JsAppsCompare:
    """Compare two builds of one JavaScript/Electron application.

    Both sides are inventoried with the same bounds (offline, nothing
    executed), then set-diffed: files by path, imports by (kind, spec),
    dependencies by name and version pin, IPC channels by literal name.

    Args:
        left_path: Extracted app directory or .asar archive (older side).
        right_path: Extracted app directory or .asar archive (newer side).
        max_files: File-row ceiling passed to both inventories.

    Returns:
        The bounded :class:`JsAppsCompare`.

    Raises:
        AnalysisError: When either side cannot be inventoried.
    """
    left = analyze_javascript_app(Path(left_path), max_files=max_files).to_dict()
    right = analyze_javascript_app(Path(right_path), max_files=max_files).to_dict()

    warnings: list[str] = list(left.get("warnings", ()))
    warnings.extend(right.get("warnings", ()))
    for side, payload in (("left", left), ("right", right)):
        if payload.get("truncated"):
            warnings.append(f"{side} inventory hit its file cap; the diff is partial")

    left_files = _file_rows(left)
    right_files = _file_rows(right)

    files_added: list[FileChange] = []
    files_removed: list[FileChange] = []
    files_changed: list[FileChange] = []
    role_changes: list[FileChange] = []

    for path in sorted(set(left_files) - set(right_files)):
        files_removed.append(FileChange(path=path, kind="removed"))
    for path in sorted(set(right_files) - set(left_files)):
        files_added.append(FileChange(path=path, kind="added"))
    for path in sorted(set(left_files) & set(right_files)):
        before = _import_set(left_files[path])
        after = _import_set(right_files[path])
        role_left = str(left_files[path].get("role") or "unknown")
        role_right = str(right_files[path].get("role") or "unknown")
        if before != after:
            files_changed.append(
                FileChange(
                    path=path,
                    kind="changed",
                    role_left=role_left,
                    role_right=role_right,
                    imports_added=tuple(sorted(after - before)),
                    imports_removed=tuple(sorted(before - after)),
                )
            )
        if role_left != role_right:
            role_changes.append(
                FileChange(path=path, kind="changed", role_left=role_left, role_right=role_right)
            )

    left_versions = _package_versions(left)
    right_versions = _package_versions(right)
    packages: list[PackageChange] = []
    for name in sorted(set(left_versions) - set(right_versions)):
        packages.append(PackageChange(name=name, kind="removed"))
    for name in sorted(set(right_versions) - set(left_versions)):
        packages.append(PackageChange(name=name, kind="added"))
    for name in sorted(set(left_versions) & set(right_versions)):
        if left_versions[name] != right_versions[name]:
            packages.append(
                PackageChange(
                    name=name,
                    kind="version",
                    version_left=left_versions[name],
                    version_right=right_versions[name],
                )
            )

    left_ipc = _channel_index(left)
    right_ipc = _channel_index(right)
    ipc: list[IpcChange] = []
    for channel in sorted(set(left_ipc) - set(right_ipc)):
        ipc.append(IpcChange(channel=channel, kind="removed"))
    for channel in sorted(set(right_ipc) - set(left_ipc)):
        ipc.append(IpcChange(channel=channel, kind="added"))
    for channel in sorted(set(left_ipc) & set(right_ipc)):
        # A channel that was paired and lost one side in the newer build is a
        # boundary change worth its own row: the surviving side now talks to
        # nobody (main_only) or answers nobody (renderer_only).
        had_both = left_ipc[channel]["main"] and left_ipc[channel]["renderer"]
        has_main = right_ipc[channel]["main"]
        has_renderer = right_ipc[channel]["renderer"]
        if had_both and has_main and not has_renderer:
            ipc.append(
                IpcChange(
                    channel=channel,
                    kind="main_only",
                    files=tuple(sorted(right_ipc[channel]["files"])),
                )
            )
        elif had_both and has_renderer and not has_main:
            ipc.append(
                IpcChange(
                    channel=channel,
                    kind="renderer_only",
                    files=tuple(sorted(right_ipc[channel]["files"])),
                )
            )

    truncated_flag = [bool(left.get("truncated")) or bool(right.get("truncated"))]
    if files_changed:
        warnings.append(
            "a changed import set proves the module changed, not what the change does; "
            "file contents are not hashed into this comparison"
        )

    return JsAppsCompare(
        left_root=str(left.get("root") or left_path),
        right_root=str(right.get("root") or right_path),
        left_kind=str(left.get("kind") or "unknown"),
        right_kind=str(right.get("kind") or "unknown"),
        files_added=_bounded_rows(files_added, "files added", truncated_flag, warnings),
        files_removed=_bounded_rows(files_removed, "files removed", truncated_flag, warnings),
        files_changed=_bounded_rows(files_changed, "files changed", truncated_flag, warnings),
        role_changes=_bounded_rows(role_changes, "role changes", truncated_flag, warnings),
        packages=_bounded_rows(packages, "packages", truncated_flag, warnings),
        ipc=_bounded_rows(ipc, "ipc channels", truncated_flag, warnings),
        left_file_count=int(left.get("file_count") or 0),
        right_file_count=int(right.get("file_count") or 0),
        truncated=truncated_flag[0],
        warnings=tuple(warnings),
    )

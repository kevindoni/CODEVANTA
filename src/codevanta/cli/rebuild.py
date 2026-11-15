"""Rebuild projects: Study → Build → Check → Ready (storytold/Craft Anything style).

A rebuild project records a request to recreate a target, studies the target
with CODEVANTA's analysis engine, and tracks an agent-built recreation through
comparison checks against the original.

Project layout (under ``--root``, default ``~/.codevanta/rebuilds/<id>/``)::

    craft.json        # request, target, mode, status, history
    capture/          # study results recorded from the target
    app/              # the generated recreation (built by a coding agent)
    checks/           # each comparison against the original
    investigation.cany/  # evidence records
    inbox/            # open questions (unanswered decisions)

Modes:

* **clean-room** (default): only surface inspection — no code or files read
  inside the original. Tools that would look inside are refused and say how to
  turn on Deep mode.
* **deep**: every CODEVANTA analysis tool is used on the target, for private
  use only.

Nothing here launches a coding agent or writes to the network. The `rebuild`
command scaffolds the project and records the study; an external agent (Claude
Code, Copilot, Grok Build via ACP, ...) does the building, and `rebuild check`
compares the result against the original.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from codevanta.analysis.compare import compare_artifacts
from codevanta.core.disassembler import DisassemblyError
from codevanta.core.entropy import analyze_entropy
from codevanta.core.functions import discover_functions
from codevanta.core.loader import BinaryInfo, BinaryLoader, BinaryLoadError
from codevanta.core.report import AnalysisError
from codevanta.core.strings import StringExtractor
from codevanta.evidence.confidence import Confidence

__all__ = [
    "DEFAULT_MAX_CHECKS",
    "DEFAULT_MAX_STUDY_ENTRIES",
    "REBUILD_SCHEMA_VERSION",
    "STATUS_TRANSITIONS",
    "VALID_MODES",
    "app",
    "build_project",
    "check_build",
    "list_projects",
    "rebuild_build",
    "rebuild_build_auto",
    "rebuild_check",
    "rebuild_inbox",
    "rebuild_ready",
    "rebuild_list",
    "rebuild_show",
    "rebuild_start",
    "study_target",
]

REBUILD_SCHEMA_VERSION = 1
DEFAULT_MAX_CHECKS = 10
DEFAULT_MAX_STUDY_ENTRIES = 200

# Valid status transitions: studied -> building -> checked -> ready
# studied -> checked is also allowed (projects can skip the formal build step)
# checked -> checked allows re-checking after modifications
STATUS_TRANSITIONS: dict[str, list[str]] = {
    "studied": ["building", "checked"],
    "building": ["checked"],
    "checked": ["checked", "ready"],
    "ready": [],
}

VALID_STATUSES = {"studied", "building", "checked", "ready"}
VALID_MODES = {"clean-room", "deep"}


def _validate_transition(current: str, target: str) -> None:
    allowed = STATUS_TRANSITIONS.get(current, [])
    if target not in allowed:
        raise typer.BadParameter(
            f"invalid status transition {current!r} -> {target!r}; "
            f"allowed from {current!r}: {allowed}"
        )

app = typer.Typer(
    name="rebuild",
    help="Rebuild projects: Study → Build → Check → Ready.",
    no_args_is_help=True,
)
console = Console()


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StudyEntry:
    """One recorded observation about a target."""

    kind: str  # "info", "functions", "strings", "xrefs", "entropy", "disasm"
    source: str  # where it came from
    confidence: Confidence
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "source": self.source,
            "confidence": self.confidence.value,
            "detail": self.detail,
        }
        if self.extra:
            data["extra"] = dict(self.extra)
        return data


@dataclass(frozen=True)
class ProjectRecord:
    """The serialized state of one rebuild project (craft.json payload)."""

    id: str
    name: str
    target: str
    request: str
    mode: str  # "clean-room" or "deep"
    status: str  # "studied", "building", "checked", "ready"
    created_at: str
    updated_at: str
    study_entries: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    inbox: list[dict[str, Any]] = field(default_factory=list)
    schema_version: int = REBUILD_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "request": self.request,
            "mode": self.mode,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "study_entries": self.study_entries,
            "checks": self.checks,
            "inbox": self.inbox,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectRecord:
        return cls(
            id=data["id"],
            name=data["name"],
            target=data["target"],
            request=data["request"],
            mode=data.get("mode", "clean-room"),
            status=data.get("status", "studied"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            study_entries=data.get("study_entries", []),
            checks=data.get("checks", []),
            inbox=data.get("inbox", []),
            schema_version=data.get("schema_version", REBUILD_SCHEMA_VERSION),
        )


# --------------------------------------------------------------------------- #
# Project layout helpers
# --------------------------------------------------------------------------- #


def _default_root() -> Path:
    configured = os.environ.get("CODEVANTA_REBUILD_ROOT")
    if configured and configured.strip():
        return Path(configured)
    return Path.home() / ".codevanta" / "rebuilds"


def _project_dir(root: Path, project_id: str) -> Path:
    return root / project_id


def _craft_path(project_dir: Path) -> Path:
    return project_dir / "craft.json"


def _ensure_dirs(project_dir: Path) -> None:
    for sub in ("capture", "app", "checks", "investigation.cany", "inbox"):
        (project_dir / sub).mkdir(parents=True, exist_ok=True)


def _evidence_dir(project_dir: Path) -> Path:
    return project_dir / "investigation.cany"


def _write_evidence(
    project_dir: Path,
    kind: str,
    payload: dict[str, Any],
    confidence: str | None = None,
    coverage: str | None = None,
    limitations: str | None = None,
) -> Path:
    """Append one evidence record to investigation.cany/evidence.jsonl."""
    ev_dir = _evidence_dir(project_dir)
    ev_dir.mkdir(parents=True, exist_ok=True)
    path = ev_dir / "evidence.jsonl"
    record: dict[str, Any] = {
        "id": uuid.uuid4().hex[:8],
        "kind": kind,
        "created_at": _now_iso(),
        "payload": payload,
    }
    if confidence is not None:
        record["confidence"] = confidence
    if coverage is not None:
        record["coverage"] = coverage
    if limitations is not None:
        record["limitations"] = limitations
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_id() -> str:
    return uuid.uuid4().hex[:12]


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _slug(text: str, max_len: int = 40) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_ " else "-" for ch in text)
    safe = "-".join(safe.split())
    return safe[:max_len] or "project"


# --------------------------------------------------------------------------- #
# Study: inspect a target and record observations
# --------------------------------------------------------------------------- #


def _study_binary(
    path: Path, mode: str, max_entries: int
) -> tuple[list[StudyEntry], list[str]]:
    """Study a binary target with CODEVANTA's analysis engine.

    Clean-room mode keeps to metadata (info, strings, entropy) — nothing that
    reads code inside the file. Deep mode adds functions, xrefs and disassembly
    of the entry point.
    """
    entries: list[StudyEntry] = []
    warnings: list[str] = []
    remaining = max_entries

    def add(kind: str, source: str, confidence: Confidence, detail: str, extra: dict[str, Any] | None = None) -> None:
        nonlocal remaining
        if remaining <= 0:
            return
        entries.append(StudyEntry(kind, source, confidence, detail, extra or {}))
        remaining -= 1

    try:
        loaded = BinaryLoader().load(path)
    except BinaryLoadError as exc:
        warnings.append(f"cannot load target for study: {exc}")
        return entries, warnings

    # info — metadata is surface inspection, allowed in both modes
    info = {
        "format": loaded.format,
        "architecture": loaded.architecture,
        "bitness": loaded.bitness,
        "endianness": loaded.endianness,
        "entry_point": f"0x{loaded.entry_point:x}" if loaded.entry_point is not None else None,
        "image_base": f"0x{loaded.image_base:x}",
        "sections": len(loaded.sections),
        "imports": len(loaded.imports),
        "exports": len(loaded.exports),
        "symbols": len(loaded.symbols),
        "stripped": loaded.is_stripped,
    }
    add(
        "info",
        "binary.metadata",
        Confidence.CERTAIN,
        f"{loaded.format} binary, {loaded.architecture} {loaded.bitness}-bit, "
        f"{len(loaded.sections)} sections, {len(loaded.imports)} imports, "
        f"{len(loaded.exports)} exports",
        extra={"metadata": info},
    )

    # strings — surface inspection, allowed in both modes
    try:
        strings = StringExtractor(min_length=4).extract(path, info=loaded, limit=50)
        add(
            "strings",
            "binary.strings",
            Confidence.CERTAIN,
            f"{len(strings)} strings extracted (first {min(len(strings), 50)})",
            extra={"count": len(strings), "sample": [s.text[:60] for s in strings[:10]]},
        )
    except AnalysisError as exc:
        warnings.append(f"string extraction skipped: {exc}")

    # entropy — surface inspection, allowed in both modes
    try:
        entropy = analyze_entropy(path, loaded)
        packed = [s.name for s in entropy.sections if s.packed_hint]
        add(
            "entropy",
            "binary.entropy",
            Confidence.MEDIUM,
            f"per-section Shannon entropy; {len(packed)} packed-hint section(s)"
            if packed
            else "no section above the packing threshold",
            extra={
                "packed_hint_sections": packed,
                "max_entropy": max(
                    (s.entropy for s in entropy.sections if s.entropy is not None), default=None
                ),
            },
        )
    except AnalysisError as exc:
        warnings.append(f"entropy analysis skipped: {exc}")

    # deep mode: read inside the file
    if mode == "deep":
        # functions — reads executable sections
        try:
            functions = discover_functions(loaded)
            add(
                "functions",
                "binary.functions",
                Confidence.MEDIUM,
                f"{len(functions)} function candidates discovered",
                extra={
                    "count": len(functions),
                    "sources": sorted({f.source for f in functions}),
                    "sample": [
                        {
                            "address": f"0x{f.address:x}",
                            "name": f.name or "<unknown>",
                            "source": f.source,
                            "confidence": f.confidence.value,
                        }
                        for f in functions[:10]
                    ],
                },
            )
        except AnalysisError as exc:
            warnings.append(f"function discovery skipped: {exc}")

        # xrefs — reads executable sections
        try:
            xrefs = __import__("codevanta.analysis.xrefs", fromlist=["find_xrefs"]).find_xrefs(
                path, loaded
            )
            add(
                "xrefs",
                "binary.xrefs",
                Confidence.CERTAIN,
                f"{len(xrefs.xrefs)} direct cross references recovered",
                extra={"count": len(xrefs.xrefs), "kinds": sorted({x.kind for x in xrefs.xrefs})},
            )
        except AnalysisError as exc:
            warnings.append(f"xref scan skipped: {exc}")

        # disasm of entry point
        if loaded.entry_point is not None:
            try:
                from codevanta.core.report import disassemble_region

                region = disassemble_region(path, loaded, loaded.entry_point, count=16)
                add(
                    "disasm",
                    "binary.disasm",
                    Confidence.CERTAIN,
                    f"{len(region.instructions)} instructions at entry point "
                    f"0x{loaded.entry_point:x}",
                    extra={
                        "address": f"0x{loaded.entry_point:x}",
                        "count": len(region.instructions),
                        "instructions": [i.text for i in region.instructions[:8]],
                    },
                )
            except (AnalysisError, DisassemblyError) as exc:
                warnings.append(f"entry-point disassembly skipped: {exc}")

    return entries, warnings


def study_target(
    target: str, mode: str = "clean-room", max_entries: int = DEFAULT_MAX_STUDY_ENTRIES
) -> tuple[list[StudyEntry], list[str], BinaryInfo | None]:
    """Study ``target`` and return study entries plus warnings.

    For a file target the binary loader is used. For anything else (a URL,
    directory, or unreadable path) only a surface observation is recorded.
    """
    if mode not in ("clean-room", "deep"):
        raise typer.BadParameter("mode must be 'clean-room' or 'deep'")
    path = Path(target)
    warnings: list[str] = []

    if path.exists() and path.is_file():
        entries, bin_warnings = _study_binary(path, mode, max_entries)
        warnings.extend(bin_warnings)
        loaded: BinaryInfo | None = None
        try:
            loaded = BinaryLoader().load(path)
        except BinaryLoadError:
            loaded = None
        return entries, warnings, loaded

    # Non-file target: surface observation only (clean-room rule).
    entries = [
        StudyEntry(
            "info",
            "target.surface",
            Confidence.LOW,
            f"target {target!r} is not a readable local file; only surface "
            "inspection is available in clean-room mode",
            extra={"target": target, "kind": "non-file"},
        )
    ]
    return entries, warnings, None


# --------------------------------------------------------------------------- #
# Project lifecycle
# --------------------------------------------------------------------------- #


def build_project(
    target: str,
    request: str,
    mode: str = "clean-room",
    root: Path | None = None,
) -> ProjectRecord:
    """Create a rebuild project: study the target, scaffold the directory,
    write ``craft.json`` and return the project record.

    Does not build anything — an external coding agent owns the build. Returns
    the project record so the caller can print the next steps.
    """
    if mode not in ("clean-room", "deep"):
        raise typer.BadParameter("mode must be 'clean-room' or 'deep'")

    root = root or _default_root()
    root = Path(root)
    project_id = _project_id()
    name = _slug(request) or _slug(target)
    project_dir = _project_dir(root, project_id)
    _ensure_dirs(project_dir)

    entries, warnings, _loaded = study_target(target, mode=mode)

    capture_path = project_dir / "capture" / "study.json"
    _write_json(
        capture_path,
        {
            "target": target,
            "mode": mode,
            "entries": [e.to_dict() for e in entries],
            "warnings": warnings,
            "studied_at": _now_iso(),
        },
    )

    # Open an inbox item for every deep-mode refusal boundary.
    inbox: list[dict[str, Any]] = []
    if mode == "deep":
        inbox.append(
            {
                "id": uuid.uuid4().hex[:8],
                "question": f"Confirm deep-mode study of {target!r} is for a target you own or are allowed to examine.",
                "kind": "consent",
                "answered": False,
                "created_at": _now_iso(),
            }
        )

    record = ProjectRecord(
        id=project_id,
        name=name,
        target=target,
        request=request,
        mode=mode,
        status="studied",
        created_at=_now_iso(),
        updated_at=_now_iso(),
        study_entries=[e.to_dict() for e in entries],
        inbox=inbox,
    )
    _write_json(_craft_path(project_dir), record.to_dict())

    # Evidence: record the study outcome.
    _write_evidence(
        project_dir,
        "study",
        {
            "target": target,
            "mode": mode,
            "entry_count": len(entries),
            "warning_count": len(warnings),
            "capture": str(capture_path.relative_to(project_dir)),
        },
        confidence="medium",
        coverage="surface" if mode == "clean-room" else "deep",
        limitations=(
            "clean-room mode: only surface inspection; no code or files read "
            "inside the target"
        )
        if mode == "clean-room"
        else "deep mode: reads code and files inside the target; for private use only",
    )
    return record


def list_projects(root: Path | None = None) -> list[ProjectRecord]:
    """List every rebuild project under ``root``."""
    root = root or _default_root()
    root = Path(root)
    if not root.exists():
        return []
    records: list[ProjectRecord] = []
    for child in sorted(root.iterdir()):
        craft = _craft_path(child)
        if craft.is_file():
            try:
                records.append(ProjectRecord.from_dict(_read_json(craft)))
            except (ValueError, OSError):
                continue
    records.sort(key=lambda r: r.updated_at, reverse=True)
    return records


def get_project(project_id: str, root: Path | None = None) -> ProjectRecord | None:
    """Load one project by id, or ``None`` when it does not exist."""
    root = root or _default_root()
    root = Path(root)
    craft = _craft_path(_project_dir(root, project_id))
    if not craft.is_file():
        return None
    try:
        return ProjectRecord.from_dict(_read_json(craft))
    except (ValueError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Check: compare a build against the original
# --------------------------------------------------------------------------- #


def check_build(
    project_id: str,
    build_path: Path,
    root: Path | None = None,
) -> dict[str, Any]:
    """Compare ``build_path`` against the project's original target and record
    the check under ``checks/``. Returns the check payload.

    For binary targets this runs :func:`codevanta.analysis.compare.compare_artifacts`;
    for anything else it compares file hashes and sizes.
    """
    root = root or _default_root()
    root = Path(root)
    record = get_project(project_id, root)
    if record is None:
        raise typer.Exit(code=2)

    target_path = Path(record.target)
    build_path = Path(build_path)
    check_id = uuid.uuid4().hex[:8]
    checked_at = _now_iso()
    check_dir = _project_dir(root, project_id) / "checks" / check_id
    check_dir.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "id": check_id,
        "project_id": project_id,
        "target": record.target,
        "build_path": str(build_path),
        "checked_at": checked_at,
        "result": {},
    }

    if target_path.is_file() and build_path.is_file():
        try:
            comparison = compare_artifacts("metadata", target_path, build_path)
            payload["result"] = (
                comparison.to_dict()
                if hasattr(comparison, "to_dict")
                else comparison
            )
        except Exception as exc:  # noqa: BLE001 — any comparison failure is recorded, not fatal
            payload["result"] = {"error": str(exc)}
    else:
        # Fallback: hash + size comparison for non-binary or missing files.
        def _hash(p: Path) -> str:
            h = hashlib.sha256()
            with p.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()

        target_hash = _hash(target_path) if target_path.is_file() else None
        build_hash = _hash(build_path) if build_path.is_file() else None
        payload["result"] = {
            "target_sha256": target_hash,
            "build_sha256": build_hash,
            "identical": target_hash is not None and target_hash == build_hash,
            "target_size": target_path.stat().st_size if target_path.is_file() else None,
            "build_size": build_path.stat().st_size if build_path.is_file() else None,
        }

    _write_json(check_dir / "check.json", payload)

    # Append to the project record's checks list and transition status to checked.
    updated = replace(record, updated_at=checked_at)
    checks = list(record.checks)
    checks.append(
        {
            "id": check_id,
            "build_path": str(build_path),
            "checked_at": checked_at,
            "identical": payload["result"].get("identical", False),
        }
    )
    _validate_transition(updated.status, "checked")
    updated = replace(updated, checks=checks, status="checked")
    _write_json(_craft_path(_project_dir(root, project_id)), updated.to_dict())

    # Evidence: record the check outcome.
    _write_evidence(
        _project_dir(root, project_id),
        "check",
        {
            "check_id": check_id,
            "project_id": project_id,
            "build_path": str(build_path),
            "identical": payload["result"].get("identical", False),
            "result": payload["result"],
        },
    )
    return payload


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _print_study_entries(entries: list[dict[str, Any]]) -> None:
    table = Table(title=f"Study entries ({len(entries)})")
    table.add_column("Kind")
    table.add_column("Source")
    table.add_column("Confidence")
    table.add_column("Detail")
    for entry in entries:
        table.add_row(
            escape(entry["kind"]),
            escape(entry["source"]),
            escape(entry["confidence"]),
            Text(entry["detail"], no_wrap=False),
        )
    console.print(table)


@app.command(name="start")
def rebuild_start(
    target: Annotated[str, typer.Argument(help="Target to study: a local file, directory or URL")],
    request: Annotated[
        str, typer.Argument(help="What to build, e.g. 'Recreate this website in React'")
    ],
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Study mode: 'clean-room' (surface only, default) or 'deep' (all analysis tools)",
        ),
    ] = "clean-room",
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """Start a rebuild project: study the target, scaffold the directory,
    write ``craft.json``. An external coding agent then builds the recreation.

    Study → Build → Check → Ready. This command runs the Study step.
    """
    try:
        record = build_project(target, request, mode=mode, root=root)
    except typer.BadParameter as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    project_dir = _project_dir(root or _default_root(), record.id)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column()
    grid.add_row("Project", record.id)
    grid.add_row("Name", record.name)
    grid.add_row("Target", record.target)
    grid.add_row("Request", record.request)
    grid.add_row("Mode", record.mode)
    grid.add_row("Status", record.status)
    grid.add_row("Directory", str(project_dir))
    console.print(Panel(grid, title="CODEVANTA · rebuild project created"))

    console.print("\n[bold]Study entries:[/]")
    _print_study_entries(record.study_entries)

    if record.inbox:
        console.print("\n[bold]Open questions (inbox):[/]")
        for item in record.inbox:
            console.print(f"  • {item['question']}")

    console.print(
        "\n[dim]Next: a coding agent builds the recreation in "
        f"{escape(str(project_dir / 'app'))}, then run:[/]"
    )
    console.print(
        f"[bold]codevanta rebuild check {record.id} <path-to-build>[/]"
    )


@app.command(name="list")
def rebuild_list(
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """List rebuild projects, most recently updated first."""
    records = list_projects(root)
    if not records:
        console.print("[dim]no rebuild projects[/]")
        return
    table = Table(title=f"Rebuild projects ({len(records)})")
    table.add_column("Id")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Mode")
    table.add_column("Target")
    table.add_column("Updated")
    for record in records:
        table.add_row(
            record.id,
            escape(record.name),
            escape(record.status),
            escape(record.mode),
            escape(record.target),
            escape(record.updated_at),
        )
    console.print(table)


@app.command(name="show")
def rebuild_show(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """Show one project's record: request, status, study entries, checks, inbox."""
    record = get_project(project_id, root)
    if record is None:
        console.print(f"[bold red]error:[/] project {project_id!r} not found")
        raise typer.Exit(code=2)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column()
    grid.add_row("Id", record.id)
    grid.add_row("Name", record.name)
    grid.add_row("Target", record.target)
    grid.add_row("Request", record.request)
    grid.add_row("Mode", record.mode)
    grid.add_row("Status", record.status)
    grid.add_row("Created", record.created_at)
    grid.add_row("Updated", record.updated_at)
    console.print(Panel(grid, title=f"CODEVANTA · rebuild {record.id}"))

    console.print(f"\n[bold]Study entries ({len(record.study_entries)}):[/]")
    _print_study_entries(record.study_entries)

    if record.checks:
        console.print(f"\n[bold]Checks ({len(record.checks)}):[/]")
        table = Table()
        table.add_column("Id")
        table.add_column("Build path")
        table.add_column("Checked")
        table.add_column("Identical")
        for check in record.checks:
            table.add_row(
                escape(check["id"]),
                escape(check["build_path"]),
                escape(check["checked_at"]),
                "yes" if check.get("identical") else "no",
            )
        console.print(table)

    if record.inbox:
        console.print(f"\n[bold]Open questions ({len(record.inbox)}):[/]")
        for item in record.inbox:
            answered = " [green](answered)[/]" if item.get("answered") else ""
            console.print(f"  • {item['question']}{answered}")


@app.command(name="check")
def rebuild_check(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    build_path: Annotated[
        Path, typer.Argument(help="Path to the agent-built recreation to compare")
    ],
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """Compare a build against the project's original target and record the
    check. Prints a similarity summary.

    This is the Check step: the build is compared with the original and the
    result is saved under ``checks/``. The project status moves to ``checked``.
    """
    try:
        payload = check_build(project_id, build_path, root=root)
    except typer.Exit:
        raise

    result = payload["result"]
    console.print(
        f"[bold]Check {payload['id']}[/] — {escape(payload['target'])} vs "
        f"{escape(str(build_path))}"
    )
    if result.get("identical"):
        console.print("[green]identical[/]")
    elif "error" in result:
        console.print(f"[yellow]comparison could not run: {escape(result['error'])}[/]")
    else:
        console.print(f"[dim]target sha256: {result.get('target_sha256')}[/]")
        console.print(f"[dim]build sha256:  {result.get('build_sha256')}[/]")
        console.print(f"[dim]target size:  {result.get('target_size')}[/]")
        console.print(f"[dim]build size:   {result.get('build_size')}[/]")
        console.print("[yellow]not identical — hashes differ[/]")

    console.print(
        f"\n[dim]Check saved under checks/{payload['id']}/check.json[/]"
        "\n[dim]Next: open the build, review the diff, ask for changes, then re-check.[/]"
    )


# --------------------------------------------------------------------------- #
# Build: scaffold the recreation directory
# --------------------------------------------------------------------------- #


def _suggest_stack(entries: list[dict[str, Any]]) -> str:
    """Heuristically suggest a build stack from study entries."""
    kinds = {e.get("kind") for e in entries}
    sources = set()
    for e in entries:
        for s in e.get("extra", {}).get("sources", []):
            sources.add(s)
    if "pe" in sources or "elf" in sources or "mach-o" in sources:
        return "native"
    if "functions" in kinds or "xrefs" in kinds:
        return "native"
    return "generic"


def _write_app_scaffold(
    project_dir: Path,
    record: ProjectRecord,
    stack: str,
) -> list[Path]:
    """Write starter files into ``app/`` for the coding agent to fill in.

    Returns the list of files written.
    """
    app_dir = project_dir / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    readme = app_dir / "README.md"
    readme.write_text(
        f"# {record.name}\n\n"
        f"Target: {record.target}\n"
        f"Request: {record.request}\n"
        f"Mode: {record.mode}\n"
        f"Suggested stack: {stack}\n\n"
        "## Study notes\n"
        "See ``../capture/study.json`` for the recorded observations about the "
        "original target. Use them as the spec for this recreation.\n\n"
        "## Checks\n"
        "Run ``codevanta rebuild check <id> <build-path>`` to compare this "
        "recreation against the original.\n",
        encoding="utf-8",
    )
    written.append(readme)

    if stack == "native":
        stub = app_dir / "main.c"
        stub.write_text(
            f"/* Rebuild target: {record.target} */\n"
            "#include <stdio.h>\n\n"
            "int main(void) {\n"
            f'    printf("rebuild of {record.target}\\n");\n'
            "    return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        written.append(stub)
    else:
        stub = app_dir / "app.py"
        stub.write_text(
            f"# Rebuild target: {record.target}\n"
            f'"""Recreation of {record.target}."""\n\n'
            "def main():\n"
            f'    print("rebuild of {record.target}")\n\n'
            "if __name__ == \"__main__\":\n"
            "    main()\n",
            encoding="utf-8",
        )
        written.append(stub)

    # Evidence: record the scaffold.
    _write_evidence(
        project_dir,
        "build_scaffold",
        {
            "project_id": record.id,
            "stack": stack,
            "files": [str(p.relative_to(project_dir)) for p in written],
        },
    )
    return written


# --------------------------------------------------------------------------- #
# Auto-build: code generation + iterative check loop
# --------------------------------------------------------------------------- #


def _generate_code(record: ProjectRecord, stack: str) -> dict[str, str]:
    """Generate recreation source code from study entries.

    Returns a mapping of ``filename -> source`` for files to write under
    ``app/``. Uses only information recorded during the Study step, so this
    works in clean-room mode too (surface-only observations).

    The generated code is a *working scaffold* meant for a coding agent (Cline,
    Cursor, Copilot, ...) to fill in. It contains every fact recovered about
    the target as constants/comments, plus real function signatures so the
    agent can implement logic without re-deriving everything.
    """
    entries = record.study_entries
    target = record.target
    request = record.request

    # Collect observations
    meta: dict[str, Any] = {}
    strings: list[str] = []
    functions: list[dict[str, Any]] = []
    xref_kinds: list[str] = []
    disasm: list[str] = []
    for e in entries:
        extra = e.get("extra", {})
        if e["kind"] == "info" and "metadata" in extra:
            meta = extra["metadata"]
        elif e["kind"] == "strings":
            strings = extra.get("sample", [])
        elif e["kind"] == "functions":
            functions = extra.get("sample", [])
        elif e["kind"] == "xrefs":
            xref_kinds = extra.get("kinds", [])
        elif e["kind"] == "disasm":
            disasm = extra.get("instructions", [])

    # Build a shared facts block used by both language backends.
    facts_block: list[str] = [
        f"# Rebuild of {target}",
        f"# Request: {request}",
        "# Generated by CODEVANTA rebuild (auto-build)",
        "#",
        "# STUDY FACTS (from CODEVANTA analysis of the target):",
    ]
    if meta:
        facts_block.append(f"#   format: {meta.get('format')}")
        facts_block.append(f"#   architecture: {meta.get('architecture')}")
        facts_block.append(f"#   bitness: {meta.get('bitness')}")
        facts_block.append(f"#   sections: {meta.get('sections')}")
        facts_block.append(f"#   imports: {meta.get('imports')}")
        facts_block.append(f"#   exports: {meta.get('exports')}")
        facts_block.append(f"#   stripped: {meta.get('stripped')}")
    if strings:
        facts_block.append(f"#   strings ({len(strings)}):")
        for s in strings[:10]:
            facts_block.append(f"#     - {s}")
    if functions:
        facts_block.append(f"#   functions ({len(functions)}):")
        for f in functions[:10]:
            facts_block.append(
                f"#     - {f.get('name', '<unknown>')} @ {f.get('address', '?')} "
                f"({f.get('source', '?')})"
            )
    if xref_kinds:
        facts_block.append(f"#   xref kinds: {', '.join(sorted(xref_kinds))}")
    if disasm:
        facts_block.append(f"#   entry-point disasm ({len(disasm)} instructions):")
        for i in disasm[:8]:
            facts_block.append(f"#     {i}")
    facts_block.append("#")
    facts_block.append(
        "# TODO (coding agent): implement the recreation logic below, then run:"
    )
    facts_block.append("#   codevanta rebuild check <project-id> <build-path>")
    facts_block.append("#")

    def _c_name(key: str) -> str:
        return "TARGET_" + key.upper().replace(" ", "_")

    def _safe_c_identifier(name: str, fallback: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name)
        if not safe or safe[0].isdigit():
            safe = fallback
        return safe

    if stack == "native":
        lines: list[str] = []
        lines.extend(facts_block)
        lines.append("")
        lines.append("#include <stdio.h>")
        lines.append('#include <string.h>')
        lines.append('#include <stdlib.h>')
        lines.append("")

        # Metadata constants
        if meta:
            lines.append("/* --- target metadata --- */")
            for key, value in meta.items():
                if value is not None:
                    c_name = _c_name(key)
                    if isinstance(value, str):
                        lines.append(f'#define {c_name} "{value}"')
                    else:
                        lines.append(f'#define {c_name} {value}')
            lines.append("")

        # String constants
        if strings:
            lines.append("/* --- recovered strings --- */")
            for idx, s in enumerate(strings[:20]):
                escaped = s.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'#define STR_{idx} "{escaped}"')
            lines.append("")

        # Function declarations + stubs
        if functions:
            lines.append("/* --- recovered functions (stubs) --- */")
            for f in functions[:20]:
                name = f.get("name") or f"func_{f.get('address', 'unknown')}"
                safe = _safe_c_identifier(name, f"func_{f.get('address','unknown')}")
                addr = f.get("address", "?")
                src = f.get("source", "?")
                lines.append(f"/* {safe} @ {addr} (source: {src}) */")
                lines.append(f"void {safe}(void);")
                lines.append(f"void {safe}(void) {{")
                lines.append(f'    printf("stub: {safe} called\\n");')
                lines.append("}")
                lines.append("")
        else:
            lines.append("/* no functions recovered */")
            lines.append("void placeholder_function(void) {")
            lines.append('    printf("no functions recovered\\n");')
            lines.append("}")
            lines.append("")

        lines.append("/* --- entry point --- */")
        lines.append("int main(void) {")
        lines.append(f'    printf("rebuild of {target}\\n");')
        lines.append(f'    printf("request: {request}\\n");')
        lines.append("")
        if strings:
            lines.append('    printf("\\n--- recovered strings ---\\n");')
            for idx in range(min(len(strings), 20)):
                lines.append(f'    printf("%s\\n", STR_{idx});')
        if functions:
            lines.append('    printf("\\n--- recovered functions ---\\n");')
            for f in functions[:10]:
                name = f.get("name") or f"func_{f.get('address', 'unknown')}"
                safe = _safe_c_identifier(name, f"func_{f.get('address','unknown')}")
                lines.append(f"    {safe}();")
        lines.append("    return 0;")
        lines.append("}")
        return {"main.c": "\n".join(lines) + "\n"}

    # generic -> Python
    lines = []
    lines.extend(facts_block)
    lines.append("")
    lines.append("import sys")
    lines.append("")
    lines.append(f'TARGET = {target!r}')
    lines.append(f'REQUEST = {request!r}')
    lines.append("")

    # Metadata constants
    if meta:
        lines.append("# --- target metadata ---")
        for key, value in meta.items():
            if value is not None:
                py_name = _c_name(key)
                lines.append(f"{py_name} = {value!r}")
        lines.append("")

    # String constants
    if strings:
        lines.append("# --- recovered strings ---")
        for idx, s in enumerate(strings[:20]):
            lines.append(f"STR_{idx} = {s!r}")
        lines.append("")

    # Function stubs with signatures
    if functions:
        lines.append("# --- recovered functions (stubs) ---")
        for f in functions[:20]:
            name = f.get("name") or f"func_{f.get('address', 'unknown')}"
            safe = _safe_c_identifier(name, f"func_{f.get('address','unknown')}")
            addr = f.get("address", "?")
            src = f.get("source", "?")
            lines.append(f"# {safe} @ {addr} (source: {src})")
            lines.append(f"def {safe}():")
            lines.append(f'    print("stub: {safe} called")')
            lines.append("")
    else:
        lines.append("# no functions recovered")
        lines.append("def placeholder_function():")
        lines.append('    print("no functions recovered")')
        lines.append("")

    lines.append("# --- entry point ---")
    lines.append("def main():")
    lines.append('    print(f"rebuild of {TARGET}")')
    lines.append('    print(f"request: {REQUEST}")')
    lines.append("")
    if strings:
        lines.append('    print("\\n--- recovered strings")')
        for idx in range(min(len(strings), 20)):
            lines.append(f'    print(STR_{idx})')
    if functions:
        lines.append('    print("\\n--- recovered functions")')
        for f in functions[:10]:
            name = f.get("name") or f"func_{f.get('address', 'unknown')}"
            safe = _safe_c_identifier(name, f"func_{f.get('address','unknown')}")
            lines.append(f"    {safe}()")
    lines.append("")
    lines.append('if __name__ == "__main__":')
    lines.append("    main()")
    return {"app.py": "\n".join(lines) + "\n"}


# --------------------------------------------------------------------------- #
# Build verification: actually compile / run the artifact
# --------------------------------------------------------------------------- #


def _verify_build_artifact(build_path: Path) -> dict[str, Any]:
    """Try to compile/run the build artifact and return observable output.

    For Python: run the script and capture stdout/stderr + exit code.
    For C: compile with cc/gcc if available, then run the binary.
    Returns a dict with ``ok``, ``output``, ``error``, ``exit_code``.
    """
    result: dict[str, Any] = {
        "ok": False,
        "output": None,
        "error": None,
        "exit_code": None,
    }

    if build_path.suffix.lower() == ".py":
        import subprocess

        try:
            proc = subprocess.run(
                ["python", str(build_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            result["ok"] = proc.returncode == 0
            result["output"] = proc.stdout
            result["error"] = proc.stderr
            result["exit_code"] = proc.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            result["ok"] = False
            result["error"] = str(exc)
        return result

    if build_path.suffix.lower() in (".c",):
        import shutil
        import subprocess

        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            result["ok"] = False
            result["error"] = "no C compiler found (cc/gcc/clang)"
            return result

        out_bin = build_path.with_suffix("")
        try:
            compile_proc = subprocess.run(
                [cc, "-O2", "-o", str(out_bin), str(build_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if compile_proc.returncode != 0:
                result["ok"] = False
                result["error"] = compile_proc.stderr
                result["exit_code"] = compile_proc.returncode
                return result

            run_proc = subprocess.run(
                [str(out_bin)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            result["ok"] = run_proc.returncode == 0
            result["output"] = run_proc.stdout
            result["error"] = run_proc.stderr
            result["exit_code"] = run_proc.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            result["ok"] = False
            result["error"] = str(exc)
        return result

    result["ok"] = False
    result["error"] = f"unsupported build artifact: {build_path.suffix}"
    return result


def _attempt_auto_build(
    project_id: str,
    root: Path | None = None,
    max_attempts: int = 5,
) -> dict[str, Any]:
    """Run the automated Build → Check → Improve loop.

    For each attempt: scaffold/generate code into ``app/``, run ``check_build``,
    and if the result is not identical, regenerate with adjustments. Stops when
    the build is identical or ``max_attempts`` is reached.

    Returns a summary dict with final status, attempts used, and last check.
    """
    root = root or _default_root()
    root = Path(root)
    record = get_project(project_id, root)
    if record is None:
        raise typer.Exit(code=2)

    _validate_transition(record.status, "building")

    project_dir = _project_dir(root, project_id)
    stack = _suggest_stack(record.study_entries)
    attempt = 0
    last_result: dict[str, Any] | None = None
    last_verify: dict[str, Any] | None = None

    while attempt < max_attempts:
        attempt += 1
        # Generate (or regenerate) code.
        code_files = _generate_code(record, stack)
        app_dir = project_dir / "app"
        app_dir.mkdir(parents=True, exist_ok=True)
        for name, source in code_files.items():
            (app_dir / name).write_text(source, encoding="utf-8")

        # Pick the main build artifact for comparison.
        build_path = app_dir / ("main.c" if stack == "native" else "app.py")

        # Verify the artifact actually builds/runs.
        last_verify = _verify_build_artifact(build_path)

        # Run check (transitions status to checked).
        result = check_build(project_id, build_path, root=root)
        last_result = result

        if result["result"].get("identical"):
            updated = replace(record, updated_at=_now_iso(), status="ready")
            _write_json(_craft_path(project_dir), updated.to_dict())
            _write_evidence(
                project_dir,
                "auto_build_ready",
                {
                    "project_id": project_id,
                    "attempts": attempt,
                    "stack": stack,
                },
            )
            return {
                "id": project_id,
                "status": "ready",
                "attempts": attempt,
                "stack": stack,
                "identical": True,
                "last_check": result,
                "last_verify": last_verify,
            }

        # Not identical yet: record the failure as evidence and retry.
        _write_evidence(
            project_dir,
            "auto_build_attempt",
            {
                "project_id": project_id,
                "attempt": attempt,
                "identical": False,
                "result": result["result"],
                "verify": last_verify,
            },
        )

    # Exhausted attempts: leave status at "checked".
    return {
        "id": project_id,
        "status": "checked",
        "attempts": attempt,
        "stack": stack,
        "identical": False,
        "last_check": last_result,
        "last_verify": last_verify,
    }


@app.command(name="build-auto")
def rebuild_build_auto(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
    max_attempts: Annotated[
        int, typer.Option("--max-attempts", help="Maximum build→check iterations")
    ] = 5,
) -> None:
    """Automated Build → Check → Improve loop.

    Generates code from study entries, writes it to ``app/``, runs
    ``codevanta rebuild check``, and repeats until identical or
    ``--max-attempts`` is reached. Marks the project ``ready`` on success.
    """
    summary = _attempt_auto_build(project_id, root=root, max_attempts=max_attempts)
    console.print(
        Panel(
            f"[bold]{summary['id']}[/]\n"
            f"status: {summary['status']}\n"
            f"attempts: {summary['attempts']}\n"
            f"identical: {'yes' if summary['identical'] else 'no'}",
            title="CODEVANTA · rebuild build-auto",
        )
    )
    if summary.get("last_verify"):
        v = summary["last_verify"]
        if v.get("ok"):
            console.print("[green]Build artifact compiled/ran successfully.[/]")
            if v.get("output"):
                console.print(f"[dim]output: {v['output'][:200]}[/]")
        else:
            console.print(f"[yellow]Build artifact had issues: {v.get('error')}[/]")

    if summary["identical"]:
        console.print("[green]Build matches original — project is ready.[/]")
    else:
        console.print(
            "[yellow]Build did not match original within "
            f"{max_attempts} attempts.[/]"
        )
        console.print(
            "[dim]Review app/ and checks/, adjust, then run build-auto again "
            "or mark ready manually.[/]"
        )


def _start_build(project_id: str, root: Path | None = None) -> tuple[ProjectRecord, list[Path]]:
    """Mark the project as ``building`` and scaffold the ``app/`` directory.

    Returns the updated ``ProjectRecord`` and the list of files written.
    Raises :exc:`typer.BadParameter` or :exc:`typer.Exit` on failure.
    """
    record = get_project(project_id, root)
    if record is None:
        console.print(f"[bold red]error:[/] project {project_id!r} not found")
        raise typer.Exit(code=2)

    _validate_transition(record.status, "building")

    stack = _suggest_stack(record.study_entries)
    project_dir = _project_dir(root or _default_root(), project_id)
    written = _write_app_scaffold(project_dir, record, stack)

    updated = replace(record, updated_at=_now_iso(), status="building")
    _write_json(_craft_path(project_dir), updated.to_dict())
    return updated, written


@app.command(name="build")
def rebuild_build(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """Mark the project as ``building`` and scaffold the ``app/`` directory.

    This is the Build step: the project status moves to ``building`` and
    starter files are written under ``app/`` for a coding agent to fill in.
    """
    updated, written = _start_build(project_id, root)
    project_dir = _project_dir(root or _default_root(), project_id)
    stack = _suggest_stack(updated.study_entries)

    console.print(
        Panel(
            f"[bold]{updated.id}[/]\n"
            f"status: building\n"
            f"stack: {stack}\n"
            f"directory: {project_dir / 'app'}",
            title="CODEVANTA · rebuild build started",
        )
    )
    console.print("\n[bold]Scaffolded files:[/]")
    for path in written:
        console.print(f"  • {path.relative_to(project_dir)}")
    console.print(
        "\n[dim]Next: a coding agent fills in app/, then run:[/]"
        f"\n[bold]codevanta rebuild check {updated.id} <build-path>[/]"
    )


# --------------------------------------------------------------------------- #
# Ready: mark project as ready
# --------------------------------------------------------------------------- #


def _mark_ready(project_id: str, root: Path | None = None) -> ProjectRecord:
    """Mark the project as ``ready`` after a successful check.

    Returns the updated ``ProjectRecord``. Raises :exc:`typer.BadParameter` or
    :exc:`typer.Exit` on failure (same as the CLI command).
    """
    record = get_project(project_id, root)
    if record is None:
        console.print(f"[bold red]error:[/] project {project_id!r} not found")
        raise typer.Exit(code=2)

    _validate_transition(record.status, "ready")

    if not record.checks:
        console.print(
            f"[bold red]error:[/] project {project_id!r} has no checks; "
            "run ``codevanta rebuild check`` first"
        )
        raise typer.Exit(code=2)

    last_check = record.checks[-1]
    if not last_check.get("identical"):
        console.print(
            "[bold red]error:[/] last check is not identical; "
            "fix the build and re-check before marking ready"
        )
        raise typer.Exit(code=2)

    project_dir = _project_dir(root or _default_root(), project_id)
    updated = replace(record, updated_at=_now_iso(), status="ready")
    _write_json(_craft_path(project_dir), updated.to_dict())

    # Evidence: record readiness.
    _write_evidence(
        project_dir,
        "ready",
        {
            "project_id": project_id,
            "last_check_id": last_check["id"],
        },
    )
    return updated


@app.command(name="ready")
def rebuild_ready(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """Mark the project as ``ready`` after a successful check.

    Requires the project to be in ``checked`` status and the most recent
    check to report ``identical: true``. This is the Ready step: the
    recreation has been verified against the original.
    """
    updated = _mark_ready(project_id, root)
    last_check = updated.checks[-1]
    console.print(
        Panel(
            f"[bold]{updated.id}[/]\n"
            f"status: ready\n"
            f"last check: {last_check['id']} (identical)",
            title="CODEVANTA · rebuild ready",
        )
    )


# --------------------------------------------------------------------------- #
# Inbox: answer open questions
# --------------------------------------------------------------------------- #


@app.command(name="inbox")
def rebuild_inbox(
    project_id: Annotated[str, typer.Argument(help="Project id")],
    question_id: Annotated[
        str | None, typer.Argument(help="Inbox item id to answer")
    ] = None,
    answer: Annotated[
        str | None, typer.Option("--answer", help="Answer text")
    ] = None,
    root: Annotated[
        Path | None, typer.Option("--root", help="Project root directory")
    ] = None,
) -> None:
    """List or answer inbox (open questions) for a project.

    Without arguments, lists open questions. With ``question-id`` and
    ``--answer``, marks the item as answered.
    """
    record = get_project(project_id, root)
    if record is None:
        console.print(f"[bold red]error:[/] project {project_id!r} not found")
        raise typer.Exit(code=2)

    if question_id is None:
        if not record.inbox:
            console.print("[dim]no open questions[/]")
            return
        table = Table(title=f"Inbox ({len(record.inbox)})")
        table.add_column("Id")
        table.add_column("Question")
        table.add_column("Kind")
        table.add_column("Answered")
        for item in record.inbox:
            table.add_row(
                escape(item["id"]),
                escape(item["question"]),
                escape(item.get("kind", "")),
                "yes" if item.get("answered") else "no",
            )
        console.print(table)
        return

    project_dir = _project_dir(root or _default_root(), project_id)
    inbox = list(record.inbox)
    found = False
    for item in inbox:
        if item["id"] == question_id:
            found = True
            item["answered"] = True
            item["answered_at"] = _now_iso()
            if answer is not None:
                item["answer"] = answer
            break
    if not found:
        console.print(f"[bold red]error:[/] inbox item {question_id!r} not found")
        raise typer.Exit(code=2)

    updated = replace(record, updated_at=_now_iso(), inbox=inbox)
    _write_json(_craft_path(project_dir), updated.to_dict())

    # Evidence: record the answer.
    _write_evidence(
        project_dir,
        "inbox_answer",
        {
            "project_id": project_id,
            "question_id": question_id,
            "answer": answer,
        },
    )

    console.print(f"[green]inbox item {question_id} answered[/]")


@app.command(name="make")
def rebuild_make(
    target: Annotated[str, typer.Argument(help="Target to study: a local file, directory or URL")],
    request: Annotated[
        str, typer.Argument(help="What to build, e.g. 'Recreate this website in React'")
    ],
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Study mode: 'clean-room' (surface only, default) or 'deep' (all analysis tools)",
        ),
    ] = "clean-room",
    project_folder: Annotated[
        Path | None, typer.Option("--project-folder", help="Project root directory")
    ] = None,
    existing: Annotated[
        str | None,
        typer.Option(
            "--existing",
            help="How to treat an existing project: 'skip-study' (reuse, don't restudy) or 'edit' (keep and rebuild)",
        ),
    ] = None,
    max_attempts: Annotated[
        int, typer.Option("--max-attempts", help="Maximum build→check iterations")
    ] = 5,
) -> None:
    """Study a target and run the Build → Check → Improve loop in one command.

    Mirrors ``craft-anything-cli rebuild <target> "<description>"``: runs the
    Study step, scaffolds the project, generates code into ``app/``, checks it
    against the original, and repeats until identical or ``--max-attempts`` is
    reached. Marks the project ``ready`` on success.

    Use ``--existing skip-study`` to reuse an already-studied project without
    restudying the target. Use ``--project-folder`` to choose where the
    project directory is created.
    """
    root = Path(project_folder) if project_folder else _default_root()

    if existing == "skip-study":
        # Reuse an already-studied project: find it by target+request under root.
        record = get_project(target, root=root) if len(target) <= 40 else None
        if record is None:
            # Try matching by target string among existing projects.
            for cand in list_projects(root=root):
                if cand.target == target:
                    record = cand
                    break
        if record is None:
            console.print(
                f"[bold red]error:[/] no existing project found for target "
                f"{target!r} under {root}. Run without --existing first."
            )
            raise typer.Exit(code=2)
        project_id = record.id
        console.print(
            f"[dim]Reusing existing project {project_id} (study skipped).[/]"
        )
    else:
        record = build_project(target, request, mode=mode, root=root)
        project_id = record.id

        project_dir = _project_dir(root, project_id)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan")
        grid.add_column()
        grid.add_row("Project", record.id)
        grid.add_row("Name", record.name)
        grid.add_row("Target", record.target)
        grid.add_row("Request", record.request)
        grid.add_row("Mode", record.mode)
        grid.add_row("Status", record.status)
        grid.add_row("Directory", str(project_dir))
        console.print(Panel(grid, title="CODEVANTA · rebuild project created"))

        console.print("\n[bold]Study entries:[/]")
        _print_study_entries(record.study_entries)

    console.print(
        f"\n[bold]Running Build → Check → Improve loop "
        f"(max {max_attempts} attempts)...[/]"
    )
    summary = _attempt_auto_build(project_id, root=root, max_attempts=max_attempts)

    console.print(
        Panel(
            f"[bold]{summary['id']}[/]\n"
            f"status: {summary['status']}\n"
            f"attempts: {summary['attempts']}\n"
            f"identical: {'yes' if summary['identical'] else 'no'}",
            title="CODEVANTA · rebuild make",
        )
    )

    if summary.get("last_verify"):
        v = summary["last_verify"]
        if v.get("ok"):
            console.print("[green]Build artifact compiled/ran successfully.[/]")
            if v.get("output"):
                console.print(f"[dim]output: {v['output'][:200]}[/]")
        else:
            console.print(f"[yellow]Build artifact had issues: {v.get('error')}[/]")

    if summary["identical"]:
        console.print("[green]Build matches original — project is ready.[/]")
    else:
        console.print(
            "[yellow]Build did not match original within "
            f"{max_attempts} attempts.[/]"
        )
        console.print(
            "[dim]Review app/ and checks/, adjust, then run build-auto again "
            "or mark ready manually.[/]"
        )

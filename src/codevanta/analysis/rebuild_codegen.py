"""Rebuild starter-code generator (lane-codegen).

Closes the pipeline gap between Study and Build: :func:`generate_starter`
reads a studied rebuild project (the ``craft.json`` + ``capture/`` layout
written by :mod:`codevanta.cli.rebuild`) and deterministically writes
runnable starter files into ``output_directory``:

* ``app/main.py`` -- a header comment block citing the target and the
  evidence digest, one import-surface block per observed API group
  (``kernel32``/``ws2_32``/``user32`` ... grouped from the capture's
  ``imports`` entries) and one ``raise NotImplementedError`` stub per group
  citing the evidence (reference count + example symbol).
* ``app/pseudo_c/*.c`` -- the decompiled pseudo-C recorded by deep-mode
  study, so the TODO markers in the stubs can point at real evidence files.
* ``ui_layout.json`` + ``ui.html`` -- the dialog-evidence widget tree and a
  deterministic HTML preview (reusing
  :func:`codevanta.analysis.winres_ui.render_preview_html`) when a dialog
  decode capture exists.
* ``checks/behavior_checklist.md`` -- one deterministic checklist item per
  check the study recorded.

Determinism: nothing here reads the wall clock or generates random ids.
Identical inputs produce byte-identical files (verified in tests). All work
is bounded (``MAX_FILES``, ``MAX_STUBS``, ``MAX_LINES_PER_FILE``) and every
bound overrun is reported through manifest warnings/truncation flags instead
of unbounded output. Every error is a typed
:class:`~codevanta.core.report.AnalysisError`; every written path is
sanitized so nothing escapes ``output_directory``.
"""

from __future__ import annotations

import hashlib
import json
import keyword
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from codevanta.analysis import winres_ui
from codevanta.core.report import AnalysisError
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

__all__ = [
    "MAX_FILES",
    "MAX_LINES_PER_FILE",
    "MAX_NAME_CHARS",
    "MAX_STUBS",
    "CodegenManifest",
    "SUPPORTED_LANGUAGES",
    "generate_starter",
]

#: Files written per run (bounded work).
MAX_FILES = 32

#: Stub functions generated per run (bounded work).
MAX_STUBS = 256

#: Lines per generated file (bounded output).
MAX_LINES_PER_FILE = 2000

#: Characters per sanitized path/name component (bounded output).
MAX_NAME_CHARS = 64

#: Largest capture file read (oversize inputs are typed errors).
MAX_CAPTURE_BYTES = 4 * 1024 * 1024

#: Languages the generator can emit (only Python today).
SUPPORTED_LANGUAGES = ("python",)

_PSEUDO_C_DIR = "pseudo_c"


@dataclass(frozen=True)
class CodegenManifest:
    """JSON-safe summary of one :func:`generate_starter` run."""

    project_dir: str
    output_directory: str
    language: str
    target: str
    evidence_digest: str
    files: tuple[dict[str, Any], ...]
    stub_count: int
    group_count: int
    dialog_count: int
    check_count: int
    files_truncated: bool
    stubs_truncated: bool
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_dir": self.project_dir,
            "output_directory": self.output_directory,
            "language": self.language,
            "target": self.target,
            "evidence_digest": self.evidence_digest,
            "files": [dict(f) for f in self.files],
            "stub_count": self.stub_count,
            "group_count": self.group_count,
            "dialog_count": self.dialog_count,
            "check_count": self.check_count,
            "files_truncated": self.files_truncated,
            "stubs_truncated": self.stubs_truncated,
            "warnings": list(self.warnings),
        }


# --------------------------------------------------------------------------- #
# Sanitizing / bounds helpers
# --------------------------------------------------------------------------- #


def _sanitize_component(raw: str, fallback: str = "unnamed") -> str:
    """Reduce ``raw`` to one safe path component (no traversal, bounded)."""
    text = (raw or "").replace("\\", "/").split("/")[-1]
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in text)
    safe = safe.lstrip(".").strip()
    safe = safe[:MAX_NAME_CHARS]
    return safe or fallback


def _python_identifier(raw: str, fallback: str = "api_group") -> str:
    """Reduce ``raw`` to a valid, bounded Python identifier."""
    text = (raw or "").strip().lower()
    parts = [ch if (ch.isalnum() or ch == "_") else "_" for ch in text]
    name = "".join(parts).strip("_")[:MAX_NAME_CHARS].strip("_")
    if not name:
        name = fallback
    if name[0].isdigit():
        name = f"api_{name}"
    if keyword.iskeyword(name):
        name = f"{name}_"
    return name


def _oversize_guard(path: Path) -> None:
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise AnalysisError(f"capture file too large to generate from: {path}")


def _read_json_file(path: Path, what: str) -> Any:
    try:
        _oversize_guard(path)
        return json.loads(path.read_text(encoding="utf-8"))
    except AnalysisError:
        raise
    except (OSError, ValueError) as exc:
        raise AnalysisError(f"unreadable {what}: {path} ({exc})") from exc


# --------------------------------------------------------------------------- #
# Evidence reading
# --------------------------------------------------------------------------- #


def _load_study_entries(
    project_dir: Path, warnings: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load craft.json and the capture entries it describes."""
    craft_path = project_dir / "craft.json"
    if not craft_path.is_file():
        raise AnalysisError(f"not a rebuild study project (missing craft.json): {project_dir}")
    craft = _read_json_file(craft_path, "craft.json")
    if not isinstance(craft, dict):
        raise AnalysisError(f"craft.json is not a JSON object: {craft_path}")

    capture_path = project_dir / "capture" / "study.json"
    entries: list[dict[str, Any]] = []
    if capture_path.is_file():
        capture = _read_json_file(capture_path, "capture/study.json")
        if isinstance(capture, dict):
            raw_entries = capture.get("entries", [])
            if isinstance(raw_entries, list):
                entries = [e for e in raw_entries if isinstance(e, dict)]
            else:
                warnings.append("capture/study.json 'entries' is not a list; ignored")
        else:
            warnings.append("capture/study.json is not a JSON object; ignored")
    else:
        warnings.append("capture/study.json missing; falling back to craft.json study_entries")
    if not entries:
        raw_entries = craft.get("study_entries", [])
        if isinstance(raw_entries, list):
            entries = [e for e in raw_entries if isinstance(e, dict)]
    return craft, entries


def _api_groups(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group observed imports from the capture entries (deterministic order).

    Deep-mode study records one ``imports`` entry whose ``extra.libraries``
    maps each imported library to its observed symbol names. Several such
    entries are merged; ordering is sorted by sanitized group key.
    """
    groups: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.get("kind") != "imports":
            continue
        extra = entry.get("extra") or {}
        libraries = extra.get("libraries")
        if not isinstance(libraries, dict):
            continue
        for lib, names in libraries.items():
            if not isinstance(lib, str) or not isinstance(names, list):
                continue
            symbol_names = [n for n in names if isinstance(n, str) and n]
            key = _python_identifier(lib)
            # Library names carry a trailing ".dll" that the sanitizer turns
            # into "_dll"; the documented group keys (kernel32/ws2_32/user32)
            # drop it so the stub reads kernel32_surface(), not kernel32_dll_surface().
            if key.endswith("_dll"):
                key = key[: -len("_dll")]
            bucket = groups.setdefault(
                key, {"library": lib, "symbols": [], "source": str(entry.get("source", ""))}
            )
            known = set(bucket["symbols"])
            for sym in symbol_names:
                if sym not in known:
                    bucket["symbols"].append(sym)
                    known.add(sym)
    return {key: groups[key] for key in sorted(groups)}


def _decompile_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The deep-mode pseudo-C evidence entries, in capture order."""
    return [e for e in entries if e.get("kind") == "decompile" and isinstance(e.get("extra"), dict)]


def _find_dialog_evidence(project_dir: Path) -> Path | None:
    """Locate a dialog-decode JSON capture (``codevanta_dialog_decode`` shape)."""
    capture_dir = project_dir / "capture"
    if not capture_dir.is_dir():
        return None
    for path in sorted(capture_dir.glob("*.json")):
        try:
            _oversize_guard(path)
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (AnalysisError, OSError, ValueError):
            continue
        if isinstance(doc, dict) and "dialog_count" in doc and isinstance(doc.get("dialogs"), list):
            return path
    return None


# --------------------------------------------------------------------------- #
# Starter file bodies
# --------------------------------------------------------------------------- #


def _render_main_py(
    target: str,
    project_name: str,
    digest: str,
    groups: dict[str, dict[str, Any]],
    pseudo_files: list[dict[str, str]],
    warnings: list[str],
) -> tuple[str, int]:
    """Build the ``app/main.py`` starter source; return (text, stubs emitted)."""
    lines: list[str] = [
        f'"""Starter recreation of {target}.',
        "",
        "Generated by codevanta_rebuild_generate from the study evidence.",
        f"Project: {project_name}",
        f"Evidence digest (sha256): {digest}",
        "",
        "Every stub below is a surface recovered from capture/study.json;",
        "fill the bodies in, then run the rebuild checks against the original.",
        '"""',
        "",
    ]
    stubs_emitted = 0
    if not groups:
        lines.extend(
            [
                "# no API groups observed in the capture evidence",
                "def main() -> None:",
                '    """Entry point of the recreation."""',
                '    print("rebuild starter: no API groups recorded yet")',
                "",
                'if __name__ == "__main__":',
                "    main()",
                "",
            ]
        )
        return "\n".join(lines), 0

    pseudo_note = f"; pseudo-C evidence: {pseudo_files[0]['path']}" if pseudo_files else ""
    for key, group in groups.items():
        symbols = group["symbols"]
        example = symbols[0] if symbols else "<none>"
        surface_line = ", ".join(symbols[:25]) + (" ..." if len(symbols) > 25 else "")
        todo = f"# TODO: rebuild from capture evidence ({group['source'] or 'capture/study.json'})"
        block = [
            f"# === import surface: {group['library']} ({len(symbols)} observed symbol(s)) ===",
            f"# {surface_line}",
            f"def {key}_surface() -> None:",
            f'    """{group["library"]} surface: {len(symbols)} reference(s), example: {example}."""',
            todo + pseudo_note,
            "    raise NotImplementedError  # TODO: implement from the study evidence",
            "",
        ]
        if len(lines) + len(block) > MAX_LINES_PER_FILE:
            warnings.append(
                f"main.py capped at {MAX_LINES_PER_FILE} lines (MAX_LINES_PER_FILE); "
                f"{stubs_emitted}/{len(groups)} stubs emitted"
            )
            break
        lines.extend(block)
        stubs_emitted += 1

    lines.extend(
        [
            'if __name__ == "__main__":',
            "    # starter: surfacing the observed API groups is left to the agent",
            "    pass",
            "",
        ]
    )
    return "\n".join(lines), stubs_emitted


def _behavior_checklist_md(checks: list[dict[str, Any]], target: str) -> str:
    """One deterministic markdown checklist item per recorded check."""
    lines = [
        "# Behavior checklist",
        "",
        f"Target: {target}",
        "",
    ]
    if not checks:
        lines.extend(
            [
                "- [ ] (no checks recorded yet; run `codevanta rebuild check` first)",
                "",
            ]
        )
        return "\n".join(lines)
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_id = str(check.get("id", "unknown"))
        kind = str(check.get("kind", "build"))
        checked_at = str(check.get("checked_at", ""))
        outcome = "unknown"
        if check.get("behavior_match") is not None:
            outcome = "match" if check["behavior_match"] else "mismatch"
        elif check.get("identical") is not None:
            outcome = "identical" if check["identical"] else "different"
        lines.append(
            f"- [ ] check {check_id} ({kind}, {outcome}, recorded {checked_at}) - "
            "re-verify after the starter code is implemented"
        )
    lines.append("")
    return "\n".join(lines)




# --------------------------------------------------------------------------- #
# Dialog evidence -> ui_layout.json + ui.html
# --------------------------------------------------------------------------- #


def _confidence_from_value(value: Any) -> Confidence:
    try:
        return Confidence(str(value))
    except ValueError:
        return Confidence.UNKNOWN


def _summary_from_dialog_doc(doc: dict[str, Any]) -> winres_ui.WinResUiSummary:
    """Rebuild a :class:`winres_ui.WinResUiSummary` from its ``to_dict`` shape."""
    raw_evidence = doc.get("evidence")
    evidence = (
        Evidence(
            source=str(raw_evidence.get("source", winres_ui.EVIDENCE_SOURCE)),
            method=str(raw_evidence.get("method", "dialog-decode-capture")),
            confidence=_confidence_from_value(raw_evidence.get("confidence", "high")),
            detail=raw_evidence.get("detail"),
            extra=raw_evidence.get("extra") or {},
        )
        if isinstance(raw_evidence, dict)
        else Evidence(
            source=winres_ui.EVIDENCE_SOURCE,
            method="dialog-decode-capture",
            confidence=Confidence.HIGH,
        )
    )
    dialogs = tuple(d for d in doc.get("dialogs", []) if isinstance(d, dict))
    return winres_ui.WinResUiSummary(
        path=str(doc.get("path", "")),
        resource_table_present=bool(doc.get("resource_table_present", True)),
        dialog_count=int(doc.get("dialog_count", len(dialogs))),
        dialogs=dialogs,
        dialogs_truncated=bool(doc.get("dialogs_truncated", False)),
        dialog_item_count=int(doc.get("dialog_item_count", 0)),
        menu_count=int(doc.get("menu_count", 0)),
        menus=tuple(m for m in doc.get("menus", []) if isinstance(m, dict)),
        menus_truncated=bool(doc.get("menus_truncated", False)),
        stringtable_block_count=int(doc.get("stringtable_block_count", 0)),
        stringtable_entry_count=int(doc.get("stringtable_entry_count", 0)),
        stringtable_entries=tuple(
            s for s in doc.get("stringtable_entries", []) if isinstance(s, dict)
        ),
        stringtable_truncated=bool(doc.get("stringtable_truncated", False)),
        warnings=tuple(str(w) for w in doc.get("warnings", [])),
        evidence=evidence,
    )


def _minimal_preview_html(doc: dict[str, Any], title: str) -> str:
    """Fallback preview rebuilt directly from the decoded widget tree."""
    esc_title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    parts = [
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n",
        f"<title>{esc_title}</title>\n",
        "</head>\n<body>\n",
        f"<h1>{esc_title}</h1>\n",
    ]
    for dialog in doc.get("dialogs", []):
        if not isinstance(dialog, dict):
            continue
        d_title = str(dialog.get("title") or dialog.get("name") or "(unnamed dialog)")
        parts.append(f"<h2>{d_title}</h2>\n<ul>\n")
        for item in dialog.get("items", []):
            if not isinstance(item, dict):
                continue
            label = str(item.get("title") or item.get("class") or "?")
            ident = item.get("id")
            parts.append(f"<li data-id=\"{ident}\">{label}</li>\n")
        parts.append("</ul>\n")
    parts.append("</body>\n</html>\n")
    return "".join(parts)




# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def generate_starter(
    project_dir: Path,
    output_directory: Path,
    language: Literal["python"] = "python",
) -> CodegenManifest:
    """Generate deterministic starter files from a studied rebuild project.

    Reads ``craft.json`` and ``capture/`` evidence from ``project_dir`` and
    writes ``app/main.py`` (import-surfaced stubs), the pseudo-C evidence
    files when deep-mode decompiles were recorded, ``ui_layout.json`` and
    ``ui.html`` when a dialog-decode capture exists, and
    ``checks/behavior_checklist.md``. Returns a JSON-safe manifest of
    everything written. Identical inputs yield byte-identical files.
    """
    project_dir = Path(project_dir)
    output_directory = Path(output_directory)
    if language not in SUPPORTED_LANGUAGES:
        raise AnalysisError(
            f"unsupported language {language!r}; supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    if not project_dir.is_dir():
        raise AnalysisError(f"project directory does not exist: {project_dir}")

    warnings: list[str] = []
    craft, entries = _load_study_entries(project_dir, warnings)
    target = str(craft.get("target", ""))

    # Evidence digest: sha256 over the content hashes of the evidence inputs.
    digest_input = bytearray()
    for rel in ("craft.json", "capture/study.json"):
        path = project_dir / rel
        if path.is_file():
            digest_input.extend(rel.encode("utf-8"))
            digest_input.extend(b"\x00")
            digest_input.extend(hashlib.sha256(path.read_bytes()).digest())
    evidence_digest = hashlib.sha256(bytes(digest_input)).hexdigest()

    raw_checks = craft.get("checks", [])
    checks = [c for c in raw_checks if isinstance(c, dict)] if isinstance(raw_checks, list) else []

    out = output_directory
    out.mkdir(parents=True, exist_ok=True)
    root = out.resolve()

    def _resolve(rel_parts: tuple[str, ...]) -> Path:
        """Resolve a sanitized relative path, refusing traversal out of ``out``."""
        safe_parts = tuple(_sanitize_component(p) for p in rel_parts)
        candidate = root.joinpath(*safe_parts).resolve()
        if candidate != root and root not in candidate.parents:
            raise AnalysisError(f"generated path escapes output directory: {candidate}")
        return candidate

    written: list[dict[str, Any]] = []
    files_truncated = False

    def _record(path: Path, text: str) -> None:
        nonlocal files_truncated
        if len(written) >= MAX_FILES:
            files_truncated = True
            warnings.append(
                f"file budget exhausted (MAX_FILES={MAX_FILES}); {path.name} not written"
            )
            return
        data = text.encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        written.append(
            {
                # POSIX separators keep the manifest byte-identical across
                # Windows and Linux (the check lane diffs manifests).
                "path": path.relative_to(root).as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    # --- pseudo-C evidence files (deep-mode decompile entries) ---------------
    decompiles = _decompile_entries(entries)
    pseudo_files: list[dict[str, str]] = []
    for index, entry in enumerate(decompiles[: MAX_FILES - 4]):
        extra = entry.get("extra") or {}
        body = extra.get("body")
        if not isinstance(body, str) or not body:
            continue
        name = _sanitize_component(str(extra.get("name") or f"sub_{extra.get('address', index)}"))
        rel = ("app", _PSEUDO_C_DIR, f"{index:02d}_{name}.c")
        if len(written) >= MAX_FILES:
            break
        _record(_resolve(rel), body if body.endswith("\n") else body + "\n")
        pseudo_files.append({"path": "/".join(rel), "name": name})
    if len(pseudo_files) < len(decompiles):
        files_truncated = True
        warnings.append(
            f"pseudo-C evidence truncated: {len(decompiles)} entries, "
            f"{len(pseudo_files)} written (MAX_FILES={MAX_FILES})"
        )

    # --- app/main.py ---------------------------------------------------------
    groups = _api_groups(entries)
    stubs_truncated = len(groups) > MAX_STUBS
    if stubs_truncated:
        warnings.append(
            f"stub budget exhausted: {len(groups)} API groups observed, "
            f"{MAX_STUBS} stubs written (MAX_STUBS={MAX_STUBS})"
        )
    bounded_groups = {key: groups[key] for key in sorted(groups)[:MAX_STUBS]}
    main_text, stub_count = _render_main_py(
        target, str(craft.get("name", "")), evidence_digest, bounded_groups, pseudo_files, warnings
    )
    _record(_resolve(("app", "main.py")), main_text)

    # --- dialog evidence -----------------------------------------------------
    dialog_count = 0
    dialog_source = _find_dialog_evidence(project_dir)
    if dialog_source is not None:
        doc = _read_json_file(dialog_source, "dialog evidence capture")
        if isinstance(doc, dict):
            dialog_count = int(doc.get("dialog_count", len(doc.get("dialogs", []))))
            layout_path = _resolve(("ui_layout.json",))
            layout_bytes = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            if len(written) < MAX_FILES:
                layout_path.parent.mkdir(parents=True, exist_ok=True)
                layout_path.write_bytes(layout_bytes)
                written.append(
                    {
                        "path": layout_path.relative_to(root).as_posix(),
                        "bytes": len(layout_bytes),
                        "sha256": hashlib.sha256(layout_bytes).hexdigest(),
                    }
                )
            else:
                files_truncated = True
                warnings.append("file budget exhausted before ui_layout.json")
            title = f"UI preview: {Path(target).name or 'target'}"
            html_text: str | None = None
            try:
                summary = _summary_from_dialog_doc(doc)
                html_text = winres_ui.render_preview_html(summary, title=title)
            except (AnalysisError, KeyError, TypeError, ValueError) as exc:
                warnings.append(f"preview renderer fell back to minimal HTML ({exc})")
                html_text = None
            if html_text is None:
                html_text = _minimal_preview_html(doc, title)
            if len(written) < MAX_FILES:
                _record(_resolve(("ui.html",)), html_text)
            else:
                files_truncated = True
                warnings.append("file budget exhausted before ui.html")
        else:
            warnings.append("dialog evidence capture is not a JSON object; ignored")

    # --- checks checklist ----------------------------------------------------
    if len(written) < MAX_FILES:
        checklist = _behavior_checklist_md(checks, target)
        _record(_resolve(("checks", "behavior_checklist.md")), checklist)
    else:
        files_truncated = True
        warnings.append("file budget exhausted before checks/behavior_checklist.md")

    return CodegenManifest(
        project_dir=str(project_dir),
        output_directory=str(out),
        language=language,
        target=target,
        evidence_digest=evidence_digest,
        files=tuple(written),
        stub_count=stub_count,
        group_count=len(groups),
        dialog_count=dialog_count,
        check_count=len(checks),
        files_truncated=files_truncated,
        stubs_truncated=stubs_truncated,
        warnings=tuple(warnings),
    )


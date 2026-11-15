"""Tests for the lane-codegen rebuild starter-code generator.

Builds synthetic study projects in the exact shape ``codevanta.cli.rebuild``
writes (craft.json ProjectRecord payload + capture/study.json + optional
dialog-decode capture), runs :func:`generate_starter`, and asserts on the
written files, determinism, bounds and typed errors. Nothing here executes
the generated code or touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

from codevanta.analysis.rebuild_codegen import (
    MAX_FILES,
    MAX_LINES_PER_FILE,
    MAX_STUBS,
    generate_starter,
)

# --------------------------------------------------------------------------- #
# Synthetic study-project builders (mirroring codevanta.cli.rebuild output)
# --------------------------------------------------------------------------- #


def _imports_entry(libraries: dict[str, list[str]]) -> dict:
    """One deep-mode study entry of kind ``imports`` (binary.imports)."""
    count = sum(len(names) for names in libraries.values())
    return {
        "kind": "imports",
        "source": "binary.imports",
        "confidence": "certain",
        "detail": f"{count} imports across {len(libraries)} libraries",
        "extra": {
            "count": count,
            "libraries": {lib: list(names) for lib, names in libraries.items()},
        },
    }


def _decompile_entry(name: str, body: str, address: str = "0x401000") -> dict:
    """One deep-mode study entry of kind ``decompile`` (pseudo-C)."""
    return {
        "kind": "decompile",
        "source": "binary.decompile",
        "confidence": "medium",
        "detail": f"pseudo-C of {name}",
        "extra": {"address": address, "name": name, "body": body, "truncated": False},
    }


def _craft_doc(
    entries: list[dict],
    checks: list[dict] | None = None,
    target: str = "C:/apps/widget.exe",
    name: str = "recreate-widget-app",
) -> dict:
    """craft.json payload exactly as ``ProjectRecord.to_dict`` writes it."""
    return {
        "id": "abc123def456",
        "name": name,
        "target": target,
        "request": "Recreate the widget app",
        "mode": "deep",
        "status": "studied",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "study_entries": entries,
        "checks": checks if checks is not None else [],
        "inbox": [],
        "schema_version": 1,
    }


def _capture_doc(entries: list[dict], target: str = "C:/apps/widget.exe") -> dict:
    """capture/study.json payload exactly as ``build_project`` writes it."""
    return {
        "target": target,
        "mode": "deep",
        "entries": entries,
        "warnings": [],
        "studied_at": "2026-01-01T00:00:00+00:00",
    }


def _make_project(
    tmp_path: Path,
    entries: list[dict],
    *,
    checks: list[dict] | None = None,
    capture_extra: dict[str, str] | None = None,
    target: str = "C:/apps/widget.exe",
    write_capture: bool = True,
) -> Path:
    """Write a full synthetic study project directory."""
    project = tmp_path / "proj"
    (project / "capture").mkdir(parents=True)
    (project / "craft.json").write_text(
        json.dumps(_craft_doc(entries, checks=checks, target=target), indent=2) + "\n",
        encoding="utf-8",
    )
    if write_capture:
        (project / "capture" / "study.json").write_text(
            json.dumps(_capture_doc(entries, target=target), indent=2) + "\n",
            encoding="utf-8",
        )
    for filename, text in (capture_extra or {}).items():
        (project / "capture" / filename).write_text(text, encoding="utf-8")
    return project


def _sample_entries() -> list[dict]:
    return [
        {
            "kind": "info",
            "source": "binary.metadata",
            "confidence": "certain",
            "detail": "PE binary, x86 32-bit, 3 sections, 6 imports, 1 exports",
            "extra": {"metadata": {"format": "PE"}},
        },
        _imports_entry(
            {
                "KERNEL32.dll": ["CreateFileW", "ReadFile", "CloseHandle"],
                "WS2_32.dll": ["WSAStartup", "socket"],
                "USER32.dll": ["MessageBoxW"],
            }
        ),
        _decompile_entry("WinMain", "int WinMain(void) {\n  return 0;\n}\n"),
    ]


def _dialog_capture_doc() -> dict:
    """A dialog-decode capture in ``codevanta_dialog_decode`` output shape."""
    return {
        "path": "C:/apps/widget.exe",
        "resource_table_present": True,
        "dialog_count": 1,
        "dialogs": [
            {
                "name": 100,
                "title": "Login",
                "rect_px": [0, 0, 200, 100],
                "items": [
                    {"class": "BUTTON", "title": "OK", "id": 1, "rect_px": [10, 10, 50, 14]}
                ],
            }
        ],
        "dialogs_truncated": False,
        "dialog_item_count": 1,
        "menu_count": 0,
        "menus": [],
        "menus_truncated": False,
        "stringtable_block_count": 0,
        "stringtable_entry_count": 0,
        "stringtable_entries": [],
        "stringtable_truncated": False,
        "warnings": [],
        "evidence": {
            "source": "ui.winres",
            "method": "resource-directory-walk",
            "confidence": "high",
            "detail": "1 dialog(s), 0 menu(s), 0 string(s)",
        },
    }


# --------------------------------------------------------------------------- #
# Happy path: files written with expected content markers
# --------------------------------------------------------------------------- #


def test_generate_writes_expected_files(tmp_path: Path) -> None:
    checks = [
        {
            "id": "chk1",
            "kind": "behavior",
            "build_path": "app/app.py",
            "checked_at": "2026-01-02T00:00:00+00:00",
            "behavior_match": True,
        }
    ]
    project = _make_project(tmp_path, _sample_entries(), checks=checks)
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    main_py = out / "app" / "main.py"
    checklist = out / "checks" / "behavior_checklist.md"
    pseudo = out / "app" / "pseudo_c" / "00_WinMain.c"
    assert main_py.is_file()
    assert checklist.is_file()
    assert pseudo.is_file()

    text = main_py.read_text(encoding="utf-8")
    # Header cites target + evidence digest, never a wall-clock timestamp.
    assert "C:/apps/widget.exe" in text
    assert manifest.evidence_digest in text
    # One import-surface block + one stub per observed API group.
    assert "# === import surface: KERNEL32.dll (3 observed symbol(s)) ===" in text
    assert "# === import surface: WS2_32.dll (2 observed symbol(s)) ===" in text
    assert "def kernel32_surface() -> None:" in text
    assert "def ws2_32_surface() -> None:" in text
    assert "def user32_surface() -> None:" in text
    # Stub docstring cites reference count + example symbol.
    assert "3 reference(s), example: CreateFileW" in text
    assert text.count("raise NotImplementedError") == 3
    # TODO marker references the pseudo-C evidence file.
    assert "app/pseudo_c/00_WinMain.c" in text

    checklist_text = checklist.read_text(encoding="utf-8")
    assert "# Behavior checklist" in checklist_text
    assert "check chk1 (behavior, match" in checklist_text

    assert manifest.stub_count == 3
    assert manifest.group_count == 3
    assert manifest.check_count == 1
    assert manifest.dialog_count == 0
    assert manifest.stubs_truncated is False
    paths = {f["path"] for f in manifest.files}
    assert {"app/main.py", "checks/behavior_checklist.md", "app/pseudo_c/00_WinMain.c"} <= paths
    # Manifest is JSON-safe.
    json.dumps(manifest.to_dict())


def test_starter_code_is_valid_runnable_python(tmp_path: Path) -> None:
    project = _make_project(tmp_path, _sample_entries())
    out = tmp_path / "out"
    generate_starter(project, out)
    source = (out / "app" / "main.py").read_text(encoding="utf-8")
    compile(source, "main.py", "exec")


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_generate_is_byte_identical_across_runs(tmp_path: Path) -> None:
    entries = _sample_entries() + [
        {
            "kind": "decompile",
            "source": "binary.decompile",
            "confidence": "medium",
            "detail": "pseudo-C of sub_401020",
            "extra": {
                "address": "0x401020",
                "name": None,
                "body": "/* stub */\n",
                "truncated": True,
            },
        }
    ]
    capture_extra = {"ui_dialogs.json": json.dumps(_dialog_capture_doc(), indent=2) + "\n"}
    project = _make_project(tmp_path, entries, capture_extra=capture_extra)

    manifest_one = generate_starter(project, tmp_path / "out1")
    manifest_two = generate_starter(project, tmp_path / "out2")

    rel_files_one = {
        f["path"]: (tmp_path / "out1" / f["path"]).read_bytes() for f in manifest_one.files
    }
    rel_files_two = {
        f["path"]: (tmp_path / "out2" / f["path"]).read_bytes() for f in manifest_two.files
    }
    assert set(rel_files_one) == set(rel_files_two)
    for rel, data in rel_files_one.items():
        assert rel_files_two[rel] == data, f"nondeterministic bytes in {rel}"
    one, two = manifest_one.to_dict(), manifest_two.to_dict()
    one.pop("output_directory")
    two.pop("output_directory")
    assert one == two
    # Dialog evidence made it into both runs.
    assert manifest_one.dialog_count == 1
    assert "ui.html" in rel_files_one
    assert "ui_layout.json" in rel_files_one
    assert b"Login" in rel_files_one["ui.html"]


# --------------------------------------------------------------------------- #
# Dialog evidence embedding
# --------------------------------------------------------------------------- #


def test_dialog_evidence_embeds_layout_and_preview(tmp_path: Path) -> None:
    capture_extra = {"ui_dialogs.json": json.dumps(_dialog_capture_doc(), indent=2) + "\n"}
    project = _make_project(tmp_path, _sample_entries(), capture_extra=capture_extra)
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    layout = json.loads((out / "ui_layout.json").read_text(encoding="utf-8"))
    assert layout["dialog_count"] == 1
    assert layout["dialogs"][0]["title"] == "Login"
    html = (out / "ui.html").read_text(encoding="utf-8")
    assert "Login" in html
    assert 'data-id="1"' in html
    assert manifest.dialog_count == 1


def test_dialog_evidence_minimal_preview_fallback(tmp_path: Path) -> None:
    """A widget tree without the pixel fields still yields a usable preview."""
    doc = _dialog_capture_doc()
    del doc["dialogs"][0]["rect_px"]
    doc["evidence"] = {"confidence": "nonsense-value"}  # renderer must not crash
    capture_extra = {"ui_dialogs.json": json.dumps(doc) + "\n"}
    project = _make_project(tmp_path, _sample_entries(), capture_extra=capture_extra)
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    html = (out / "ui.html").read_text(encoding="utf-8")
    assert "Login" in html
    assert manifest.dialog_count == 1
    assert any("minimal HTML" in w for w in manifest.warnings)


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def test_stub_cap_and_truncation_flag(tmp_path: Path) -> None:
    libraries = {f"LIB{i:03d}.dll": ["SymA", "SymB"] for i in range(300)}
    project = _make_project(tmp_path, [_imports_entry(libraries)])
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    assert manifest.group_count == 300
    assert manifest.stub_count == MAX_STUBS == 256
    assert manifest.stubs_truncated is True
    assert any("MAX_STUBS" in w for w in manifest.warnings)
    text = (out / "app" / "main.py").read_text(encoding="utf-8")
    assert text.count("raise NotImplementedError") == MAX_STUBS
    assert len(text.splitlines()) <= MAX_LINES_PER_FILE
    compile(text, "main.py", "exec")


def test_file_budget_bounded(tmp_path: Path) -> None:
    """More decompile entries than the file budget can hold truncates honestly."""
    entries = [_decompile_entry(f"func_{i}", f"/* {i} */\n") for i in range(64)]
    project = _make_project(tmp_path, entries)
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    assert manifest.files_truncated is True
    assert len(manifest.files) <= MAX_FILES
    assert any("truncated" in w for w in manifest.warnings)


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


def test_path_traversal_in_evidence_name_sanitized(tmp_path: Path) -> None:
    sneaky = _decompile_entry("../../../../evil", "/* pwn */\n")
    project = _make_project(tmp_path, [sneaky])
    out = tmp_path / "out"

    manifest = generate_starter(project, out)

    pseudo_files = [f["path"] for f in manifest.files if "pseudo_c" in f["path"]]
    assert pseudo_files, "expected the sanitized pseudo-C evidence file"
    for rel in pseudo_files:
        target_path = (out / rel).resolve()
        assert out.resolve() in target_path.parents
        assert ".." not in rel
    assert not (out.parent / "evil.c").exists()
    assert not (tmp_path / "evil.c").exists()



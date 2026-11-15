"""Tests for the rebuild engine (Study → Build → Check → Ready).

Covers project scaffolding, study (clean-room vs deep), listing, retrieval,
and build comparison. Nothing here executes anything or touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from codevanta.cli.rebuild import (
    DEFAULT_MAX_STUDY_ENTRIES,
    REBUILD_SCHEMA_VERSION,
    STATUS_TRANSITIONS,
    ProjectRecord,
    _attempt_auto_build,
    _generate_code,
    _mark_ready,
    _start_build,
    _verify_build_artifact,
    build_project,
    check_build,
    get_project,
    list_projects,
    rebuild_inbox,
    study_target,
)
from codevanta.evidence.confidence import Confidence


def _write_sample(path: Path, data: bytes | None = None) -> Path:
    path.write_bytes(data or b"\x7fELF" + bytes(64))
    return path


def _write_json_doc(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---- study_target -----------------------------------------------------------


def test_study_non_file_records_surface_only() -> None:
    entries, warnings, loaded = study_target("https://example.com", mode="clean-room")
    assert loaded is None
    assert len(entries) == 1
    assert entries[0].kind == "info"
    assert entries[0].confidence is Confidence.LOW
    assert "not a readable local file" in entries[0].detail
    assert warnings == []


def test_study_binary_clean_room_is_surface_only(tmp_path: Path) -> None:
    target = _write_sample(tmp_path / "sample.bin")
    entries, warnings, loaded = study_target(str(target), mode="clean-room")
    assert loaded is not None
    assert loaded.format == "ELF"
    kinds = {e.kind for e in entries}
    assert "info" in kinds
    assert "strings" in kinds
    assert "entropy" in kinds
    assert "functions" not in kinds
    assert "xrefs" not in kinds
    assert "disasm" not in kinds


def test_study_binary_deep_reads_inside(tmp_path: Path) -> None:
    target = _write_sample(tmp_path / "sample.bin")
    entries, warnings, loaded = study_target(str(target), mode="deep")
    assert loaded is not None
    kinds = {e.kind for e in entries}
    assert "info" in kinds
    # Deep mode adds functions/xrefs/disasm when the binary is decodable;
    # at minimum it must include more than clean-room.
    assert len(kinds) >= 3


def test_study_binary_deep_decompiles_for_rebuild(elf64_text_path: Path) -> None:
    """Deep study must record pseudo-C evidence an agent can rebuild from."""
    entries, warnings, loaded = study_target(str(elf64_text_path), mode="deep")
    assert loaded is not None
    kinds = {e.kind for e in entries}
    # imports entry appears whenever the loader found an import table
    if loaded.imports:
        assert "imports" in kinds
    # entry-point decompilation: the executable .text fixture is decodable
    decomp = [e for e in entries if e.kind == "decompile"]
    assert decomp, f"expected decompile evidence, kinds={kinds}, warnings={warnings}"
    body = decomp[0].extra.get("body", "")
    assert isinstance(body, str) and body
    assert len(body) <= 4200  # truncated cap plus marker


def test_study_rejects_bad_mode(tmp_path: Path) -> None:
    target = _write_sample(tmp_path / "sample.bin")
    with pytest.raises(typer.BadParameter):
        study_target(str(target), mode="invalid")  # type: ignore[arg-type]


# ---- build_project ----------------------------------------------------------


def test_build_project_scaffolds_directory(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project(
        "https://example.com",
        "Recreate this site in React",
        mode="clean-room",
        root=root,
    )
    project_dir = root / record.id
    assert project_dir.is_dir()
    assert (project_dir / "craft.json").is_file()
    assert (project_dir / "capture").is_dir()
    assert (project_dir / "app").is_dir()
    assert (project_dir / "checks").is_dir()
    assert (project_dir / "investigation.cany").is_dir()
    assert (project_dir / "inbox").is_dir()


def test_build_project_writes_craft_json(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project(
        "https://example.com",
        "Rebuild this dashboard",
        mode="deep",
        root=root,
    )
    craft = json.loads((root / record.id / "craft.json").read_text(encoding="utf-8"))
    assert craft["id"] == record.id
    assert craft["name"] == "Rebuild-this-dashboard"
    assert craft["target"] == "https://example.com"
    assert craft["request"] == "Rebuild this dashboard"
    assert craft["mode"] == "deep"
    assert craft["status"] == "studied"
    assert craft["schema_version"] == REBUILD_SCHEMA_VERSION
    assert "created_at" in craft
    assert "updated_at" in craft


def test_build_project_deep_opens_consent_inbox(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project(
        "/some/binary.bin",
        "Rebuild this tool",
        mode="deep",
        root=root,
    )
    assert len(record.inbox) == 1
    assert record.inbox[0]["kind"] == "consent"
    assert record.inbox[0]["answered"] is False
    assert "you own or are allowed to examine" in record.inbox[0]["question"]


def test_build_project_clean_room_no_inbox(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project(
        "/some/binary.bin",
        "Rebuild this tool",
        mode="clean-room",
        root=root,
    )
    assert record.inbox == []


def test_build_project_rejects_bad_mode(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    with pytest.raises(typer.BadParameter):
        build_project("x", "y", mode="invalid", root=root)  # type: ignore[arg-type]


# ---- list_projects / get_project -------------------------------------------


def test_list_projects_empty(tmp_path: Path) -> None:
    assert list_projects(root=tmp_path / "rebuilds") == []


def test_list_projects_orders_by_updated(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    build_project("t1", "request one", mode="clean-room", root=root)
    r2 = build_project("t2", "request two", mode="clean-room", root=root)
    projects = list_projects(root=root)
    assert len(projects) == 2
    assert projects[0].id == r2.id  # most recent first


def test_get_project_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project("https://example.com", "Make it in Rust", mode="deep", root=root)
    fetched = get_project(record.id, root=root)
    assert fetched is not None
    assert fetched.id == record.id
    assert fetched.request == "Make it in Rust"
    assert fetched.mode == "deep"
    assert fetched.status == "studied"


def test_get_project_missing_returns_none(tmp_path: Path) -> None:
    assert get_project("does-not-exist", root=tmp_path / "rebuilds") is None


# ---- check_build ------------------------------------------------------------


def _metadata_doc(kind: str = "metadata") -> dict:
    return {"kind": kind, "details": {"format": "ELF", "architecture": "x86_64"}}


def test_check_build_identical_files(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    build = _write_json_doc(tmp_path / "build.json", _metadata_doc())
    result = check_build(record.id, build, root=root)
    assert result["result"]["identical"] is True


def test_check_build_different_files(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc(kind="metadata"))
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    build = _write_json_doc(
        tmp_path / "build.json", _metadata_doc(kind="metadata")
    )
    # Change a detail so they differ
    build.write_text(
        json.dumps({"kind": "metadata", "details": {"format": "PE"}}),
        encoding="utf-8",
    )
    result = check_build(record.id, build, root=root)
    assert result["result"]["identical"] is False


def test_check_build_check_is_persisted(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    build = _write_json_doc(tmp_path / "build.json", _metadata_doc())
    result = check_build(record.id, build, root=root)
    check_dir = root / record.id / "checks" / result["id"]
    assert (check_dir / "check.json").is_file()
    updated = get_project(record.id, root=root)
    assert len(updated.checks) == 1
    assert updated.checks[0]["id"] == result["id"]


def test_check_build_missing_project(tmp_path: Path) -> None:
    with pytest.raises(typer.Exit):
        check_build("no-such-project", tmp_path / "build.bin", root=tmp_path / "rebuilds")


# ---- schema / constants -----------------------------------------------------


def test_schema_version_constant() -> None:
    assert REBUILD_SCHEMA_VERSION == 1


def test_default_max_study_entries() -> None:
    assert DEFAULT_MAX_STUDY_ENTRIES == 200


# ---- build command ------------------------------------------------------------


def test_start_build_transitions_to_building(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    updated, written = _start_build(record.id, root=root)
    assert updated.status == "building"
    craft = json.loads((root / record.id / "craft.json").read_text(encoding="utf-8"))
    assert craft["status"] == "building"
    assert (root / record.id / "app" / "README.md").is_file()
    assert len(written) >= 1


def test_start_build_rejects_wrong_status(tmp_path: Path) -> None:
    from codevanta.cli.rebuild import _validate_transition
    with pytest.raises(typer.BadParameter):
        _validate_transition("ready", "building")


# ---- ready command ------------------------------------------------------------


def test_mark_ready_requires_checked_status(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    with pytest.raises(typer.BadParameter):
        _mark_ready(record.id, root=root)


def test_mark_ready_requires_identical_check(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    # transition to building then checked via check_build (non-identical)
    _start_build(record.id, root=root)
    build = _write_json_doc(
        tmp_path / "build.json", _metadata_doc(kind="metadata")
    )
    build.write_text(
        json.dumps({"kind": "metadata", "details": {"format": "PE"}}),
        encoding="utf-8",
    )
    check_build(record.id, build, root=root)
    # Now status is "checked" but not identical
    with pytest.raises(typer.Exit):
        _mark_ready(record.id, root=root)


def test_mark_ready_success_when_identical(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    _start_build(record.id, root=root)
    build = _write_json_doc(tmp_path / "build.json", _metadata_doc())
    check_build(record.id, build, root=root)
    updated = _mark_ready(record.id, root=root)
    assert updated.status == "ready"
    craft = json.loads((root / record.id / "craft.json").read_text(encoding="utf-8"))
    assert craft["status"] == "ready"


# ---- inbox --------------------------------------------------------------------


def test_inbox_answer(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    record = build_project(
        "/some/binary.bin", "Rebuild this tool", mode="deep", root=root
    )
    assert len(record.inbox) == 1
    qid = record.inbox[0]["id"]
    rebuild_inbox(record.id, qid, answer="yes", root=root)
    fetched = get_project(record.id, root=root)
    answered = [i for i in fetched.inbox if i["id"] == qid]
    assert len(answered) == 1
    assert answered[0]["answered"] is True
    assert answered[0]["answer"] == "yes"


# ---- evidence -----------------------------------------------------------------


def test_evidence_written(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    ev_dir = root / record.id / "investigation.cany"
    ev_file = ev_dir / "evidence.jsonl"
    assert ev_file.is_file()
    lines = ev_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) >= 1  # at least the study evidence


# ---- status transitions -------------------------------------------------------


def test_status_transitions_constant() -> None:
    assert "studied" in STATUS_TRANSITIONS
    assert "checked" in STATUS_TRANSITIONS["studied"]
    assert "ready" in STATUS_TRANSITIONS["checked"]


# ---- code generator -------------------------------------------------------------


def test_generate_code_native_stack() -> None:
    record = ProjectRecord(
        id="p1",
        name="test",
        target="/bin/ls",
        request="Rebuild ls",
        mode="clean-room",
        status="studied",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        study_entries=[
            {
                "kind": "info",
                "source": "binary.metadata",
                "confidence": "certain",
                "detail": "ELF binary",
                "extra": {
                    "metadata": {
                        "format": "ELF",
                        "architecture": "x86_64",
                        "bitness": 64,
                        "sections": 5,
                        "imports": 10,
                        "exports": 3,
                    }
                },
            },
            {
                "kind": "strings",
                "source": "binary.strings",
                "confidence": "certain",
                "detail": "5 strings",
                "extra": {"sample": ["/usr/bin/ls", "hello world"]},
            },
        ],
        inbox=[],
    )
    code = _generate_code(record, "native")
    assert "main.c" in code
    assert "int main(void)" in code["main.c"]
    assert "/bin/ls" in code["main.c"]
    assert "Rebuild ls" in code["main.c"]
    # metadata constants emitted
    assert "TARGET_FORMAT" in code["main.c"]
    assert "TARGET_ARCHITECTURE" in code["main.c"]
    # string constants emitted
    assert "STR_0" in code["main.c"]
    assert "STR_1" in code["main.c"]
    # function stubs emitted
    assert "void placeholder_function" in code["main.c"] or "void func_" in code["main.c"] or "void main" in code["main.c"]


def test_generate_code_generic_stack() -> None:
    record = ProjectRecord(
        id="p1",
        name="test",
        target="https://example.com",
        request="Rebuild site",
        mode="clean-room",
        status="studied",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        study_entries=[],
        inbox=[],
    )
    code = _generate_code(record, "generic")
    assert "app.py" in code
    assert "def main()" in code["app.py"]
    assert 'https://example.com' in code["app.py"]


def test_generate_code_with_functions_and_strings(tmp_path: Path) -> None:
    """Generated code should embed recovered functions and strings as
    constants/stubs so a coding agent has concrete facts to work from."""
    record = ProjectRecord(
        id="p1",
        name="test",
        target="/bin/ls",
        request="Rebuild ls",
        mode="deep",
        status="studied",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        study_entries=[
            {
                "kind": "info",
                "source": "binary.metadata",
                "confidence": "certain",
                "detail": "ELF binary",
                "extra": {"metadata": {"format": "ELF", "architecture": "x86_64"}},
            },
            {
                "kind": "strings",
                "source": "binary.strings",
                "confidence": "certain",
                "detail": "2 strings",
                "extra": {"sample": ["/usr/bin/ls", "hello world"]},
            },
            {
                "kind": "functions",
                "source": "binary.functions",
                "confidence": "medium",
                "detail": "2 functions",
                "extra": {
                    "count": 2,
                    "sample": [
                        {
                            "address": "0x401000",
                            "name": "main",
                            "source": "disassembly",
                            "confidence": "high",
                        },
                        {
                            "address": "0x402000",
                            "name": "print_usage",
                            "source": "symbol table",
                            "confidence": "certain",
                        },
                    ],
                },
            },
        ],
        inbox=[],
    )
    code = _generate_code(record, "native")
    src = code["main.c"]
    assert "void main" in src or "void func_0x401000" in src
    assert "void print_usage" in src or "void func_0x402000" in src
    assert 'STR_0 = ' not in src  # C uses #define, not Python assignment
    assert "#define STR_0" in src
    assert "#define STR_1" in src

    # Python generic should use = assignment
    code_py = _generate_code(record, "generic")
    src_py = code_py["app.py"]
    assert "def main()" in src_py
    assert "STR_0 = " in src_py
    assert "STR_1 = " in src_py


# ---- auto-build -----------------------------------------------------------------


def test_attempt_auto_build_runs(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    summary = _attempt_auto_build(record.id, root=root, max_attempts=3)
    assert summary["status"] in ("ready", "checked")
    assert summary["attempts"] >= 1
    assert summary["last_check"] is not None
    assert "stack" in summary


def test_attempt_auto_build_max_attempts(tmp_path: Path) -> None:
    root = tmp_path / "rebuilds"
    target = _write_json_doc(tmp_path / "target.json", _metadata_doc())
    record = build_project(str(target), "Rebuild me", mode="clean-room", root=root)
    summary = _attempt_auto_build(record.id, root=root, max_attempts=2)
    assert summary["attempts"] == 2
    assert summary["status"] == "checked"


# ---- build verification ----------------------------------------------------------


def test_verify_build_artifact_python_ok(tmp_path: Path) -> None:
    script = tmp_path / "hello.py"
    script.write_text('print("hello")\n', encoding="utf-8")
    result = _verify_build_artifact(script)
    assert result["ok"] is True
    assert result["exit_code"] == 0
    assert "hello" in result["output"]


def test_verify_build_artifact_python_error(tmp_path: Path) -> None:
    script = tmp_path / "boom.py"
    script.write_text('raise RuntimeError("boom")\n', encoding="utf-8")
    result = _verify_build_artifact(script)
    assert result["ok"] is False
    assert result["exit_code"] != 0


def test_verify_build_artifact_unsupported(tmp_path: Path) -> None:
    file = tmp_path / "data.bin"
    file.write_bytes(b"\x00\x01\x02")
    result = _verify_build_artifact(file)
    assert result["ok"] is False
    assert "unsupported" in result["error"]


# ---- evidence confidence / coverage / limitations -----------------------------


def test_write_evidence_with_metadata(tmp_path: Path) -> None:
    from codevanta.cli.rebuild import _write_evidence
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    _write_evidence(
        project_dir,
        "study",
        {"target": "example.exe"},
        confidence="medium",
        coverage="deep",
        limitations="deep mode: reads code inside the target",
    )
    ev_file = project_dir / "investigation.cany" / "evidence.jsonl"
    assert ev_file.is_file()
    line = ev_file.read_text(encoding="utf-8").strip()
    record = json.loads(line)
    assert record["confidence"] == "medium"
    assert record["coverage"] == "deep"
    assert record["limitations"] == "deep mode: reads code inside the target"


# ---- make command -------------------------------------------------------------


def test_rebuild_make_clean_room_then_auto_build(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from codevanta.cli.rebuild import app as rebuild_app

    runner = CliRunner()
    result = runner.invoke(
        rebuild_app,
        [
            "make",
            str(tmp_path / "target.json"),
            "Recreate this in Python",
            "--mode",
            "clean-room",
            "--project-folder",
            str(tmp_path / "rebuilds"),
            "--max-attempts",
            "3",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Build → Check → Improve loop" in result.output


def test_doctor_runs() -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "CODEVANTA doctor" in result.output
    assert "Python:" in result.output

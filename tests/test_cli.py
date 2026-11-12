"""CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from codevanta.cli.main import app

runner = CliRunner()


def test_unknown_file_exits_nonzero() -> None:
    result = runner.invoke(app, ["info", "definitely-missing.bin"])
    assert result.exit_code != 0


def test_info_on_pe(pe_path: Path) -> None:
    result = runner.invoke(app, ["info", str(pe_path)])
    assert result.exit_code == 0, result.stdout
    assert "CODEVANTA" in result.stdout


def test_functions_on_elf(elf64_path: Path) -> None:
    result = runner.invoke(app, ["functions", str(elf64_path)])
    assert result.exit_code == 0, result.stdout
    assert "Function candidates" in result.stdout


def test_strings_on_elf(elf64_path: Path) -> None:
    result = runner.invoke(app, ["strings", str(elf64_path), "--min-length", "3"])
    assert result.exit_code == 0, result.stdout


def test_disasm_entry_point_on_pe(pe_path: Path) -> None:
    result = runner.invoke(app, ["disasm", str(pe_path), "--count", "5"])
    assert result.exit_code == 0, result.stdout
    assert "Disassembly at" in result.stdout


def test_analyze_writes_consistent_json(elf64_path: Path, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", str(elf64_path), "--output", str(output)]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["binary"]["format"] == "ELF"
    assert payload["provenance"]["tool"] == "codevanta"
    assert isinstance(payload["functions"], list)
    assert "strings" in payload


def test_info_on_macho(macho64_text_path: Path) -> None:
    result = runner.invoke(app, ["info", str(macho64_text_path)])
    assert result.exit_code == 0, result.stdout
    assert "CODEVANTA" in result.stdout


def test_functions_on_macho(macho64_text_path: Path) -> None:
    result = runner.invoke(app, ["functions", str(macho64_text_path)])
    assert result.exit_code == 0, result.stdout
    assert "_sample_main" in result.stdout


def test_disasm_entry_point_on_macho(macho64_text_path: Path) -> None:
    result = runner.invoke(app, ["disasm", str(macho64_text_path), "--count", "3"])
    assert result.exit_code == 0, result.stdout
    assert "Disassembly at" in result.stdout
    assert "push rbp" in result.stdout

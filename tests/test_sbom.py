"""Tests for the CycloneDX 1.6 SBOM export engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import codevanta
from codevanta.analysis.sbom import MAX_COMPONENTS, build_sbom
from codevanta.core.report import AnalysisError

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"


# ---- fixtures ---------------------------------------------------------------


@pytest.fixture
def js_app(tmp_path: Path) -> Path:
    """A small Electron-shaped application directory (same shape as the js lane)."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-app",
                "version": "1.4.0",
                "dependencies": {"electron": "33.2.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "main.js").write_text(
        "const { app } = require('electron');\n"
        "const _ = require('lodash');\n",
        encoding="utf-8",
    )
    return tmp_path


def _evidence_of(component_dict: dict) -> str:
    """The ``codevanta:evidence`` property value of one component dict."""
    properties = {
        prop["name"]: prop["value"] for prop in component_dict["properties"]
    }
    return properties["codevanta:evidence"]


# ---- JavaScript applications ------------------------------------------------


def test_js_app_components_and_purls(js_app: Path) -> None:
    """One library per external package plus the application itself."""
    report = build_sbom([js_app])
    assert report.component_count == 3
    assert [component.name for component in report.components] == [
        "demo-app",
        "electron",
        "lodash",
    ]
    by_name = {component.name: component for component in report.components}
    assert by_name["electron"].type == "library"
    assert by_name["electron"].version == "33.2.0"
    assert by_name["electron"].purl == "pkg:npm/electron@33.2.0"
    assert by_name["lodash"].type == "library"
    assert by_name["lodash"].version is None
    assert by_name["lodash"].purl == "pkg:npm/lodash"
    app = by_name["demo-app"]
    assert app.type == "application"
    assert app.purl == "pkg:npm/demo-app@1.4.0"
    assert "version" not in by_name["lodash"].to_dict()
    for component in report.components:
        assert _evidence_of(component.to_dict())


def test_js_app_without_manifest_falls_back_to_directory_name(tmp_path: Path) -> None:
    """No package.json: app name from the directory, no purl, no version."""
    (tmp_path / "index.js").write_text("const _ = require('lodash');\n", encoding="utf-8")
    report = build_sbom([tmp_path])
    app = next(c for c in report.components if c.type == "application")
    assert app.name == tmp_path.name
    assert app.purl is None
    assert app.version is None
    assert any("package.json" in warning for warning in report.warnings)


def test_version_ranges_are_not_claimed_as_versions(tmp_path: Path) -> None:
    """Ranges are demands, not facts: only exact versions reach the purl."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "ranged",
                "dependencies": {"left-pad": "^1.3.0", "lodash": "4.17.21"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text(
        "require('left-pad');\nrequire('lodash');\n", encoding="utf-8"
    )
    report = build_sbom([tmp_path])
    by_name = {component.name: component for component in report.components}
    assert by_name["left-pad"].version is None
    assert by_name["left-pad"].purl == "pkg:npm/left-pad"
    assert by_name["lodash"].purl == "pkg:npm/lodash@4.17.21"


# ---- binaries ---------------------------------------------------------------


def test_binary_application_component_from_committed_sample() -> None:
    """The committed ELF sample becomes one hashed application component."""
    sample = SAMPLES_DIR / "elf64_text.bin"
    report = build_sbom([sample])
    # Stripped section-only ELF: no dynamic-symbol libraries to lift.
    assert report.component_count == 1
    app = report.components[0]
    assert (app.type, app.name) == ("application", "elf64_text")
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert app.to_dict()["hashes"] == [{"alg": "SHA-256", "content": expected}]
    assert _evidence_of(app.to_dict()).startswith("core.loader/")
    assert app.version is None
    assert "version" not in app.to_dict()
    assert "purl" not in app.to_dict()


def test_pe_imports_become_library_components(pe_path: Path) -> None:
    """A real PE contributes its import-table libraries as components."""
    report = build_sbom([pe_path])
    libraries = [c for c in report.components if c.type == "library"]
    assert libraries, "expected import-derived library components"
    app = next(c for c in report.components if c.type == "application")
    assert app.name == pe_path.stem
    assert app.sha256 == hashlib.sha256(pe_path.read_bytes()).hexdigest()
    for library in libraries:
        assert library.version is None
        evidence = _evidence_of(library.to_dict())
        assert evidence.count("/") >= 2  # source/method/confidence
    assert any("kernel32" in library.name.lower() for library in libraries)


# ---- determinism and deduplication -------------------------------------------


def test_deterministic_serial_and_components(js_app: Path) -> None:
    """The same inputs produce a byte-identical document."""
    inputs = [SAMPLES_DIR / "elf64_text.bin", js_app]
    first = build_sbom(inputs)
    second = build_sbom(inputs)
    assert first.serial_number == second.serial_number
    assert first.components == second.components
    assert first.to_json() == second.to_json()


def test_duplicate_inputs_merge_without_duplicates(js_app: Path) -> None:
    """The same directory passed twice yields the same single-pass document."""
    single = build_sbom([js_app])
    double = build_sbom([js_app, js_app])
    assert double.component_count == single.component_count == 3
    assert double.components == single.components
    assert double.serial_number == single.serial_number
    assert not double.truncated


# ---- bounds and errors --------------------------------------------------------


def test_component_cap_truncates_honestly(js_app: Path) -> None:
    """max_components keeps the first sorted components and reports the cut."""
    report = build_sbom([js_app], max_components=1)
    assert report.truncated is True
    assert len(report.components) == 1
    assert report.component_count == 3
    assert any("component cap 1" in warning for warning in report.warnings)
    document = report.to_dict()
    assert len(document["components"]) == 1
    assert document["components"][0] == report.components[0].to_dict()


def test_typed_errors(tmp_path: Path) -> None:
    """Empty input, missing paths, unidentifiable kinds, and bad caps raise."""
    with pytest.raises(AnalysisError, match="paths must not be empty"):
        build_sbom([])
    missing = tmp_path / "does-not-exist"
    with pytest.raises(AnalysisError, match="does-not-exist"):
        build_sbom([missing])
    # A regular file that is neither .asar nor a loadable binary.
    with pytest.raises(AnalysisError, match="note.txt"):
        build_sbom([SAMPLES_DIR / "note.txt"])
    for bad in (0, -1, MAX_COMPONENTS + 1):
        with pytest.raises(AnalysisError, match="max_components"):
            build_sbom([SAMPLES_DIR / "elf64_text.bin"], max_components=bad)


# ---- document shape ------------------------------------------------------------


def test_document_shape_is_cyclonedx_1_6(js_app: Path) -> None:
    """Schema sanity: exact CycloneDX keys, tool metadata, JSON safety."""
    document = build_sbom([js_app]).to_dict()
    assert set(document) == {
        "bomFormat",
        "specVersion",
        "serialNumber",
        "version",
        "metadata",
        "components",
    }
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["version"] == 1
    assert document["serialNumber"].startswith("urn:uuid:")
    tool = document["metadata"]["tools"]["components"][0]
    assert tool["type"] == "application"
    assert tool["name"] == "codevanta"
    declared = getattr(codevanta, "__version__", None)
    if isinstance(declared, str):
        assert tool["version"] == declared
    else:
        assert "version" not in tool
    # JSON safety: strict dumps must round-trip (no Path/tuple/Enum leaks).
    assert json.loads(json.dumps(document)) == document


def test_to_json_is_pretty_document_order(js_app: Path) -> None:
    """to_json() is indent=2, insertion order (sort_keys=False)."""
    report = build_sbom([js_app])
    assert report.to_json() == json.dumps(report.to_dict(), indent=2)
    assert json.loads(report.to_json()) == report.to_dict()


# ---- CLI ------------------------------------------------------------------------


def test_cli_sbom_table_and_output_file(tmp_path: Path, js_app: Path) -> None:
    """`codevanta sbom` renders the table and -o writes the document."""
    import json as _json

    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", str(js_app)])
    assert result.exit_code == 0, result.output
    assert "CycloneDX" in result.output

    out = tmp_path / "sbom.json"
    result = runner.invoke(cli, ["sbom", str(js_app), "-o", str(out)])
    assert result.exit_code == 0, result.output
    document = _json.loads(out.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"


def test_cli_sbom_requires_a_path() -> None:
    from typer.testing import CliRunner

    from codevanta.cli.main import app as cli

    runner = CliRunner()
    result = runner.invoke(cli, ["sbom"])
    assert result.exit_code == 2
    assert "at least one PATH" in result.output

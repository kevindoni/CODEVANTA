"""Assert the static tooling contract declared by the repository.

These tests guard configuration only: the coverage floor, the mypy setup and the
CI wiring that runs both. Nothing here imports the package under test, so the
checks stay fast and independent of the analysis pipeline.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9._-]+")


def _pyproject() -> dict[str, Any]:
    """Return the parsed ``pyproject.toml``."""
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _ci_text() -> str:
    """Return the CI workflow as text so no YAML dependency is needed."""
    return CI_WORKFLOW.read_text(encoding="utf-8")


def _requirement_names(requirements: list[str]) -> set[str]:
    """Return the normalised project names of ``requirements``."""
    names: set[str] = set()
    for requirement in requirements:
        match = _REQUIREMENT_NAME.match(requirement.strip())
        assert match is not None, f"cannot parse requirement {requirement!r}"
        names.add(match.group(0).lower())
    return names


def _job_block(job: str) -> str:
    """Return the lines of one CI job (enough structure for regex checks)."""
    block: list[str] = []
    collecting = False
    for line in _ci_text().splitlines():
        if re.fullmatch(rf"  {re.escape(job)}:", line):
            collecting = True
            continue
        if not collecting:
            continue
        if line.strip() and not line.startswith("    "):
            break
        block.append(line)
    assert block, f"job {job!r} not found in {CI_WORKFLOW.name}"
    return "\n".join(block)


# --------------------------------------------------------------------------- #
# pyproject.toml
# --------------------------------------------------------------------------- #


def test_coverage_run_section_targets_the_package_with_branch_coverage() -> None:
    run = _pyproject()["tool"]["coverage"]["run"]
    assert run["source"] == ["codevanta"]
    assert run["branch"] is True


def test_coverage_report_declares_the_missing_lines_and_a_floor() -> None:
    report = _pyproject()["tool"]["coverage"]["report"]
    assert report["show_missing"] is True
    floor = report["fail_under"]
    assert isinstance(floor, int | float) and not isinstance(floor, bool)
    # The floor is a real regression gate, not a token value.
    assert 80 <= floor <= 100, floor


def test_dev_extras_carry_the_test_and_type_tooling() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]["dev"]
    names = _requirement_names(extras)
    assert {"pytest-cov", "mypy"} <= names, names


def test_dev_extras_keep_the_pre_existing_tools() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]["dev"]
    names = _requirement_names(extras)
    assert {"pytest", "ruff", "build"} <= names, names


def test_mypy_configuration_checks_the_source_tree() -> None:
    config = _pyproject()["tool"]["mypy"]
    assert config["files"] == ["src/codevanta", "scripts"]
    assert config["python_version"] == "3.10"
    assert config["ignore_missing_imports"] is True


def test_mypy_overrides_never_silence_the_whole_tree() -> None:
    overrides = _pyproject()["tool"]["mypy"].get("overrides", [])
    for entry in overrides:
        if entry.get("ignore_errors"):
            assert entry.get("module") != "*", "ignore_errors must stay module-scoped"


# --------------------------------------------------------------------------- #
# CI workflow
# --------------------------------------------------------------------------- #


def test_ci_test_job_measures_coverage() -> None:
    block = _job_block("test")
    assert "--cov=codevanta" in block
    assert "--cov-report=term-missing" in block
    assert re.search(
        r"^\s+run: python -m pytest --cov=codevanta --cov-report=term-missing$",
        block,
        re.MULTILINE,
    ), block


def test_ci_test_job_installs_the_coverage_plugin() -> None:
    block = _job_block("test")
    assert "pytest-cov" in block, block
    assert "mypy" in block, block


def test_ci_has_a_type_check_job_running_mypy() -> None:
    block = _job_block("type-check")
    # The job relies on [tool.mypy] files, which covers both src/ and scripts/.
    assert re.search(r"^\s+run: python -m mypy$", block, re.MULTILINE), block
    assert re.search(r"pip install .*\bmypy\b", block), block
    assert ".[dev]" in block, block


def test_ci_wheel_smoke_job_is_still_present() -> None:
    block = _job_block("package")
    assert "python -m build" in block
    assert ".venv-wheel/bin/codevanta --help" in block

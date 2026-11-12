"""Tests for ``scripts/agent_commit.py``, the agent commit helper.

GitHub credits a commit to the account whose verified email matches the author
email, so the helper exists to make that identity explicit and hard to mistype.
These tests cover the pure helpers plus one real commit in a throwaway repository,
which proves the resulting author and trailer without touching this checkout.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "agent_commit.py"

AGENT_NAME = "codevanta-cline"
AGENT_EMAIL = "123456789+codevanta-cline@users.noreply.github.com"


def _load_module():  # noqa: ANN202 - importlib returns a module object
    """Import the script as a module so the helpers can be tested directly."""
    spec = importlib.util.spec_from_file_location("agent_commit", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent_commit = _load_module()


def _run(args: list[str], cwd: Path | None = None):
    """Run the script with ``args`` and return the completed process."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        check=False,
        encoding="utf-8",
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Iterator[Path]:
    """Create an empty git repository with one staged file."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Maintainer"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "maintainer@example.com"], cwd=tmp_path, check=True
    )
    (tmp_path / "file.txt").write_text("content\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=tmp_path, check=True)
    yield tmp_path


def test_resolve_identity_prefers_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(agent_commit.NAME_ENV, "from-env")
    monkeypatch.setenv(agent_commit.EMAIL_ENV, "env@users.noreply.github.com")

    assert agent_commit.resolve_identity(AGENT_NAME, AGENT_EMAIL) == (AGENT_NAME, AGENT_EMAIL)


def test_resolve_identity_falls_back_to_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(agent_commit.NAME_ENV, AGENT_NAME)
    monkeypatch.setenv(agent_commit.EMAIL_ENV, AGENT_EMAIL)

    assert agent_commit.resolve_identity(None, None) == (AGENT_NAME, AGENT_EMAIL)


@pytest.mark.parametrize(("name", "email"), [(None, AGENT_EMAIL), (AGENT_NAME, None)])
def test_resolve_identity_requires_both_halves(
    monkeypatch: pytest.MonkeyPatch, name: str | None, email: str | None
) -> None:
    monkeypatch.delenv(agent_commit.NAME_ENV, raising=False)
    monkeypatch.delenv(agent_commit.EMAIL_ENV, raising=False)

    with pytest.raises(agent_commit.IdentityError):
        agent_commit.resolve_identity(name, email)


@pytest.mark.parametrize(
    "email",
    [
        AGENT_EMAIL,
        "codevanta-cline@users.noreply.github.com",
    ],
)
def test_validate_email_accepts_github_noreply(email: str) -> None:
    assert agent_commit.validate_email(email) == email


@pytest.mark.parametrize("email", ["cline@cline.bot", "agent@example.com", "not-an-email"])
def test_validate_email_rejects_unlinkable_addresses(email: str) -> None:
    with pytest.raises(agent_commit.IdentityError):
        agent_commit.validate_email(email)


def test_validate_email_can_allow_a_verified_custom_address() -> None:
    assert agent_commit.validate_email("agent@example.com", allow_any=True) == "agent@example.com"
    with pytest.raises(agent_commit.IdentityError):
        agent_commit.validate_email("no-at-sign", allow_any=True)


def test_build_command_sets_the_identity_and_trailer() -> None:
    command = agent_commit.build_command(AGENT_NAME, AGENT_EMAIL, "feat: x", ["-a"])

    assert command[:6] == [
        "git",
        "-c",
        f"user.name={AGENT_NAME}",
        "-c",
        f"user.email={AGENT_EMAIL}",
        "commit",
    ]
    assert command[6:] == [
        "-m",
        "feat: x",
        "-m",
        f"Co-authored-by: {agent_commit.CO_AUTHOR}",
        "-a",
    ]


def test_build_command_can_omit_the_trailer() -> None:
    command = agent_commit.build_command(AGENT_NAME, AGENT_EMAIL, "feat: x", [], co_author=False)

    assert not any(item.startswith("Co-authored-by:") for item in command)


def test_print_identity_reports_the_resolved_pair() -> None:
    result = _run(["--name", AGENT_NAME, "--email", AGENT_EMAIL, "--print-identity"])

    assert result.returncode == 0
    assert result.stdout.strip() == f"{AGENT_NAME} <{AGENT_EMAIL}>"


def test_rejected_email_exits_two() -> None:
    result = _run(["--name", AGENT_NAME, "--email", "cline@cline.bot", "--print-identity"])

    assert result.returncode == 2
    assert "cannot be linked to a GitHub account" in result.stderr


def test_dry_run_prints_the_command(git_repo: Path) -> None:
    result = _run(
        ["--name", AGENT_NAME, "--email", AGENT_EMAIL, "-m", "feat: x", "--dry-run", "--", "-a"],
        cwd=git_repo,
    )

    assert result.returncode == 0
    assert f"user.email={AGENT_EMAIL}" in result.stdout
    assert result.stdout.rstrip().endswith("-a")


def test_real_commit_records_the_agent_as_the_author(git_repo: Path) -> None:
    result = _run(
        ["--name", AGENT_NAME, "--email", AGENT_EMAIL, "-m", "feat: from agent"], cwd=git_repo
    )

    assert result.returncode == 0, result.stderr
    author = subprocess.run(
        ["git", "log", "-1", "--format=%an|%ae"], cwd=git_repo, capture_output=True, text=True
    ).stdout.strip()
    body = subprocess.run(
        ["git", "log", "-1", "--format=%b"], cwd=git_repo, capture_output=True, text=True
    ).stdout
    assert author == f"{AGENT_NAME}|{AGENT_EMAIL}"
    assert f"Co-authored-by: {agent_commit.CO_AUTHOR}" in body


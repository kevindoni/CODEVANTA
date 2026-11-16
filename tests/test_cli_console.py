"""The CLI must survive legacy Windows code pages.

``codevanta --help`` used to crash with ``UnicodeEncodeError`` when PowerShell
handed CPython a cp1252 ``stdout`` and rich printed its arrow characters
through the legacy Windows renderer. The regression test pins the fix in
``codevanta.cli.console``: help and a normal command both exit 0 even when the
console encoder cannot represent every glyph.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], encoding: str) -> subprocess.CompletedProcess[str]:
    """Run ``codevanta`` in a subprocess whose streams use ``encoding``."""
    return subprocess.run(
        [sys.executable, "-m", "codevanta.cli.main", *args],
        capture_output=True,
        text=True,
        encoding=encoding,
        errors="replace",
        cwd=REPO_ROOT,
        check=False,
        timeout=120,
    )


def test_help_exits_cleanly_on_legacy_code_page() -> None:
    result = _run(["--help"], encoding="cp1252")
    assert result.returncode == 0, result.stderr


def test_info_exits_cleanly_on_legacy_code_page() -> None:
    sample = REPO_ROOT / "samples" / "pe64_text.bin"
    assert sample.is_file(), f"missing sample: {sample}"
    result = _run(["info", str(sample)], encoding="cp1252")
    assert result.returncode == 0, result.stderr
    assert "pe64_text.bin" in result.stdout


def test_make_console_never_uses_legacy_renderer() -> None:
    from codevanta.cli.console import make_console

    console = make_console()
    assert console.legacy_windows is False

"""Tests for ``scripts/bench.py``, the reproducible micro-benchmark runner.

The script is exercised the way a developer runs it -- through a subprocess --
so the tests cover the parts that unit-testing the functions cannot: argument
parsing, exit status, stdout/stderr separation, and the promise that running the
benchmark writes nothing to disk. Every subprocess uses a tiny ``--repeat`` and
a small work budget so the whole module stays well under ten seconds.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_PATH = REPO_ROOT / "scripts" / "bench.py"
SAMPLES_DIR = REPO_ROOT / "samples"
ELF_SAMPLE = SAMPLES_DIR / "elf64_text.bin"
PE_SAMPLE = SAMPLES_DIR / "pe64_text.bin"

#: Tiny work budget: one run, few functions, few instructions.
TINY_ARGS = ("--repeat", "1", "--limit-functions", "16", "--max-instructions", "200")

#: Benchmarks a single input must report (``diff_binaries`` needs a pair).
SINGLE_INPUT_BENCHMARKS = {
    "load",
    "discover_functions",
    "extract_strings",
    "disassemble_entry",
    "find_xrefs",
    "build_cfg",
    "build_call_graph",
    "function_fingerprint",
    "suggest_struct",
}

#: Top-level keys of the ``--json`` document.
JSON_KEYS = {"tool", "unit", "repeat", "limits", "paths", "benchmarks", "results", "warnings"}


def run_bench(
    *args: str, cwd: Path | None = None, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    """Run ``scripts/bench.py`` in a subprocess and capture both streams."""
    return subprocess.run(
        [sys.executable, str(BENCH_PATH), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cwd or REPO_ROOT),
        timeout=timeout,
        check=False,
    )


def test_table_runs_on_elf_sample(tmp_path: Path) -> None:
    """The table run succeeds, prints a ``load`` row, and writes no files."""
    started = time.perf_counter()
    result = run_bench(str(ELF_SAMPLE), *TINY_ARGS, cwd=tmp_path)
    elapsed = time.perf_counter() - started

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].split() == ["benchmark", "path", "best_ms", "iterations"]

    rows = [line.split() for line in lines[2:] if line.strip()]
    assert rows, result.stdout
    load_rows = [row for row in rows if row[0] == "load"]
    assert load_rows, f"no 'load' row in:\n{result.stdout}"
    benchmark, path, best_ms, iterations = load_rows[0]
    assert path.endswith("elf64_text.bin")
    assert float(best_ms) >= 0.0
    assert int(iterations) == 1

    assert {row[0] for row in rows} == SINGLE_INPUT_BENCHMARKS
    assert [row[0] for row in rows] == sorted(row[0] for row in rows)
    # A tidy budget keeps this instant; a hang or a full-disk sweep is a failure.
    assert elapsed < 15.0, f"benchmark run took {elapsed:.1f}s"
    # The benchmark only reads: it must not drop artefacts next to the caller.
    assert list(tmp_path.iterdir()) == []


def test_json_output_carries_expected_keys() -> None:
    """``--json`` prints one parseable object with the documented schema."""
    result = run_bench(str(ELF_SAMPLE), "--json", *TINY_ARGS)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    assert set(payload) == JSON_KEYS
    assert payload["tool"] == "codevanta-bench"
    assert payload["unit"] == "ms"
    assert payload["repeat"] == 1
    assert payload["limits"] == {"limit_functions": 16, "max_instructions": 200}
    assert payload["paths"] == ["samples/elf64_text.bin"]
    assert set(payload["benchmarks"]) >= SINGLE_INPUT_BENCHMARKS

    results = payload["results"]
    assert results
    for row in results:
        assert set(row) == {"benchmark", "path", "best_ms", "iterations"}
        assert row["path"] == "samples/elf64_text.bin"
        assert float(row["best_ms"]) >= 0.0
        assert row["iterations"] == 1
    names = [row["benchmark"] for row in results]
    assert names == sorted(names)
    assert set(names) == SINGLE_INPUT_BENCHMARKS


def test_missing_path_exits_one_with_message(tmp_path: Path) -> None:
    """A path that cannot be loaded fails loudly instead of half-reporting."""
    missing = tmp_path / "does_not_exist.bin"
    result = run_bench(str(missing))

    assert result.returncode == 1
    assert "cannot load" in result.stderr
    assert "does_not_exist.bin" in result.stderr
    assert result.stdout.strip() == ""


def test_two_paths_add_a_diff_row() -> None:
    """Two inputs add exactly one ``diff_binaries`` row naming both files."""
    result = run_bench(str(ELF_SAMPLE), str(PE_SAMPLE), *TINY_ARGS)
    assert result.returncode == 0, result.stderr

    diff_rows = [line for line in result.stdout.splitlines() if line.startswith("diff_binaries")]
    assert len(diff_rows) == 1, result.stdout
    assert "->" in diff_rows[0]
    assert "elf64_text.bin" in diff_rows[0]
    assert "pe64_text.bin" in diff_rows[0]

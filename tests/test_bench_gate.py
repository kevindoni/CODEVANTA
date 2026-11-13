"""Tests for ``scripts/bench_gate.py``, the micro-benchmark regression gate.

The gate is exercised the way CI runs it -- through a subprocess -- so the tests
cover the parts that unit-testing the functions cannot: exit status, the shape of
the committed baseline file, stdout/stderr separation, and the promise that
nothing but the baseline is ever written. Every run uses a single sample with a
tiny work budget and ``--repeat 1`` so the module finishes in a few seconds; the
handful of pure functions are tested in-process at the end.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
GATE_PATH = SCRIPTS_DIR / "bench_gate.py"
ELF_SAMPLE = REPO_ROOT / "samples" / "elf64_text.bin"

#: Label bench.py gives the ELF sample, i.e. the path component of a baseline key.
ELF_LABEL = "samples/elf64_text.bin"

#: Tiny work budget: one sample, one run, few functions, few instructions.
TINY_ARGS = (
    "--samples",
    str(ELF_SAMPLE),
    "--repeat",
    "1",
    "--limit-functions",
    "16",
    "--max-instructions",
    "200",
)

#: Benchmarks a single input must report (``diff_binaries`` needs a pair).
SINGLE_INPUT_BENCHMARKS = (
    "build_call_graph",
    "build_cfg",
    "disassemble_entry",
    "discover_functions",
    "extract_strings",
    "find_xrefs",
    "function_fingerprint",
    "load",
    "suggest_struct",
)

#: Top-level keys of the ``--json`` report.
REPORT_KEYS = {
    "tool",
    "unit",
    "tolerance",
    "repeat",
    "limits",
    "samples",
    "baseline",
    "passed",
    "failures",
    "results",
    "warnings",
}


def run_gate(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    """Run ``scripts/bench_gate.py`` in a subprocess and capture both streams."""
    return subprocess.run(
        [sys.executable, str(GATE_PATH), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(REPO_ROOT),
        timeout=timeout,
        check=False,
    )


def record_baseline(path: Path) -> None:
    """Record a fresh baseline at ``path`` with the tiny budget."""
    result = run_gate(*TINY_ARGS, "--baseline", str(path), "--update-baseline")
    assert result.returncode == 0, result.stderr
    assert path.is_file()


def test_loose_tolerance_passes(tmp_path: Path) -> None:
    """A run inside a generous tolerance exits 0 and prints the full table."""
    baseline = tmp_path / "baseline.json"
    record_baseline(baseline)

    result = run_gate(*TINY_ARGS, "--baseline", str(baseline), "--tolerance", "5")

    assert result.returncode == 0, result.stderr
    table = result.stdout.splitlines()
    assert table[0].split() == ["benchmark", "baseline_ms", "current_ms", "delta%", "status"]
    assert "regressed" not in result.stdout
    # Every benchmark of a single input is a row of the table.
    for benchmark in SINGLE_INPUT_BENCHMARKS:
        assert f"{benchmark} ({ELF_LABEL})" in result.stdout
    assert "PASS" in result.stderr


def test_tiny_baseline_fails_and_names_the_benchmark(tmp_path: Path) -> None:
    """An impossible baseline exits 1 and the offending row is named."""
    # Everything generous except one benchmark, whose reference is a nanosecond.
    benchmarks = {f"{name} ({ELF_LABEL})": 100.0 for name in SINGLE_INPUT_BENCHMARKS}
    benchmarks[f"function_fingerprint ({ELF_LABEL})"] = 0.000001
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "format": "codevanta-bench-gate",
                "version": 1,
                "unit": "ms",
                "repeat": 1,
                "benchmarks": benchmarks,
            }
        ),
        encoding="utf-8",
    )

    result = run_gate(*TINY_ARGS, "--baseline", str(baseline))

    assert result.returncode == 1, result.stderr
    assert f"function_fingerprint ({ELF_LABEL})" in result.stdout
    assert "regressed" in result.stdout
    assert f"function_fingerprint ({ELF_LABEL})" in result.stderr
    assert "FAIL 1/" in result.stderr


def test_update_baseline_writes_sorted_json(tmp_path: Path) -> None:
    """``--update-baseline`` writes the only file it may write, deterministically."""
    baseline = tmp_path / "baseline.json"

    result = run_gate(*TINY_ARGS, "--baseline", str(baseline), "--update-baseline")

    assert result.returncode == 0, result.stderr
    assert [path.name for path in tmp_path.iterdir()] == ["baseline.json"]
    raw = baseline.read_bytes()
    assert b"\r\n" not in raw  # LF everywhere, so a Windows checkout shows no diff
    assert raw.endswith(b"\n")

    document = json.loads(raw.decode("utf-8"))
    assert document["format"] == "codevanta-bench-gate"
    assert document["unit"] == "ms"
    assert document["repeat"] == 1
    assert list(document) == sorted(document)
    assert list(document["benchmarks"]) == sorted(document["benchmarks"])
    assert document["benchmarks"]
    for value in document["benchmarks"].values():
        assert isinstance(value, float)
        assert value == round(value, 3)


def test_missing_baseline_exits_two(tmp_path: Path) -> None:
    """No baseline and no ``--update-baseline`` is exit 2, and writes nothing."""
    baseline = tmp_path / "absent" / "baseline.json"

    result = run_gate(*TINY_ARGS, "--baseline", str(baseline))

    assert result.returncode == 2
    assert "no baseline" in result.stderr
    assert "--update-baseline" in result.stderr
    assert result.stdout == ""
    assert not baseline.exists()


def test_json_report_parses(tmp_path: Path) -> None:
    """``--json`` puts one parseable document on stdout and nothing else."""
    baseline = tmp_path / "baseline.json"
    record_baseline(baseline)

    result = run_gate(*TINY_ARGS, "--baseline", str(baseline), "--tolerance", "5", "--json")

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)  # stdout is exactly one JSON document
    assert set(report) == REPORT_KEYS
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["unit"] == "ms"
    assert report["tolerance"] == 5.0
    assert report["samples"] == [ELF_LABEL]
    assert len(report["results"]) == len(SINGLE_INPUT_BENCHMARKS)
    for row in report["results"]:
        assert {"benchmark", "baseline_ms", "current_ms", "delta_pct", "status"} <= set(row)
        assert row["status"] == "ok"


# ---------------------------------------------------------------------------
# The pure functions, in process: the rule itself is worth pinning down.
# ---------------------------------------------------------------------------

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import bench_gate  # noqa: E402  (the script adds src/ to sys.path on import)


def make_row(best_ms: float, iterations: int = 3) -> bench_gate.bench.Row:
    """Build the ``bench.Row`` the measurement helpers would return."""
    return bench_gate.bench.Row(
        benchmark="load", path=ELF_LABEL, best_ms=best_ms, iterations=iterations
    )


def test_threshold_is_baseline_times_one_plus_tolerance() -> None:
    """The exact boundary: 1.5x a 1.0 ms baseline passes at 50%, 1.5001 does not."""
    row = make_row(1.5)
    key = bench_gate.row_key(row)

    at_limit = bench_gate.compare([row], {key: 1.0}, 0.5)
    assert [(verdict.status, verdict.failed) for verdict in at_limit] == [("ok", False)]
    assert at_limit[0].delta_pct == 50.0

    above = bench_gate.compare([make_row(1.5001)], {key: 1.0}, 0.5)
    assert [(verdict.status, verdict.failed) for verdict in above] == [("regressed", True)]

    # A tolerance of 0 means "any slowdown fails"; a fast run is always fine.
    assert bench_gate.compare([make_row(1.0)], {key: 1.0}, 0.0)[0].status == "ok"
    assert bench_gate.compare([make_row(0.5)], {key: 1.0}, 0.0)[0].status == "ok"


def test_missing_and_unmeasured_rows() -> None:
    """No baseline entry fails; a refused row is skipped and fails nothing."""
    row = make_row(2.0)
    verdicts = bench_gate.compare([row], {}, 0.5)
    assert [(verdict.status, verdict.failed) for verdict in verdicts] == [("missing", True)]

    refused = bench_gate.compare([make_row(0.0, iterations=0)], {bench_gate.row_key(row): 1.0}, 0.5)
    assert [(verdict.status, verdict.failed) for verdict in refused] == [("skipped", False)]
    assert refused[0].current_ms is None

    # A baseline row that was not measured this time is reported, not failed.
    stale = bench_gate.compare([], {bench_gate.row_key(row): 1.0}, 0.5)
    assert [(verdict.status, verdict.failed) for verdict in stale] == [("unmeasured", False)]


def test_repeat_never_drops_below_the_baseline() -> None:
    """``--repeat`` may raise the run count but never undercut the baseline's."""
    baseline = bench_gate.Baseline(benchmarks={}, repeat=15)
    assert bench_gate.effective_repeat(1, baseline) == 15
    assert bench_gate.effective_repeat(15, baseline) == 15
    assert bench_gate.effective_repeat(40, baseline) == 40
    assert bench_gate.effective_repeat(1, None) == 1


def test_merge_best_keeps_the_faster_pass() -> None:
    """A confirmation pass keeps the better measurement of each row."""
    slow = [make_row(2.0)]
    fast = [make_row(1.0)]
    assert [row.best_ms for row in bench_gate.merge_best(slow, fast)] == [1.0]
    assert [row.best_ms for row in bench_gate.merge_best(fast, slow)] == [1.0]

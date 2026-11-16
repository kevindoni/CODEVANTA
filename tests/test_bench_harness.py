"""Smoke tests for the in-process sample benchmark harness in ``bench/``."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_SCRIPT = REPO_ROOT / "bench" / "run_codevanta.py"
TASKS_FILE = REPO_ROOT / "bench" / "tasks.json"
SAMPLE_DIR = REPO_ROOT / "samples"


def _load_harness():
    spec = importlib.util.spec_from_file_location("run_codevanta", BENCH_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


def test_benchmark_definition_has_twelve_tasks() -> None:
    tasks = harness.load_tasks(TASKS_FILE)
    assert len(tasks) == 16
    assert len({task["id"] for task in tasks}) == 16


def test_cheap_pe64_tasks_succeed_and_estimate_tokens() -> None:
    tasks = {task["id"]: task for task in harness.load_tasks(TASKS_FILE)}
    results = [
        harness.run_task(tasks[task_id], SAMPLE_DIR)
        for task_id in ("pe64-info", "pe64-functions")
    ]
    for result in results:
        assert result["ok"], result["error"]
        assert result["approx_tokens"] > 0
        assert result["sha256"]
        assert result["error"] is None
